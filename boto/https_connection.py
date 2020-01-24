# Copyright 2007,2011 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This file is derived from
# http://googleappengine.googlecode.com/svn-history/r136/trunk/python/google/appengine/tools/https_wrapper.py


"""Extensions to allow HTTPS requests with SSL certificate validation."""

import re
import socket
import ssl

import boto

from boto.compat import six, http_client


class InvalidCertificateException(http_client.HTTPException):
    """Raised when a certificate is provided with an invalid hostname."""

    def __init__(self, host, cert, reason):
        """Constructor.

        Args:
          host: The hostname the connection was made to.
          cert: The SSL certificate (as a dictionary) the host returned.
        """
        http_client.HTTPException.__init__(self)
        self.host = host
        self.cert = cert
        self.reason = reason

    def __str__(self):
        return ('Host %s returned an invalid certificate (%s): %s' %
                (self.host, self.reason, self.cert))


def GetValidHostsForCert(cert):
    """Returns a list of valid host globs for an SSL certificate.

    Args:
      cert: A dictionary representing an SSL certificate.
    Returns:
      list: A list of valid host globs.
    """
    if 'subjectAltName' in cert:
        return [x[1] for x in cert['subjectAltName'] if x[0].lower() == 'dns']
    else:
        return [x[0][1] for x in cert['subject']
                if x[0][0].lower() == 'commonname']


def ValidateCertificateHostname(cert, hostname):
    """Validates that a given hostname is valid for an SSL certificate.

    Args:
      cert: A dictionary representing an SSL certificate.
      hostname: The hostname to test.
    Returns:
      bool: Whether or not the hostname is valid for this certificate.
    """
    hosts = GetValidHostsForCert(cert)
    boto.log.debug(
        "validating server certificate: hostname=%s, certificate hosts=%s",
        hostname, hosts)
    for host in hosts:
        host_re = host.replace('.', '\.').replace('*', '[^.]*')
        if re.search('^%s$' % (host_re,), hostname, re.I):
            return True
    return False


# Note: CertValidatingHTTPSConnection MUST use HTTPSConnection as a base class
# when running under AppEngine.
#
# AppEngine uses a custom implementation of httplib (imported in this file as
# http_client) that uses urlfetch under the hood. The custom HTTPConnection and
# HTTPSConnection classes define a private `_protocol` property that indicates
# the protocol to use when constructing URLs for urlfetch. If HTTPConnection
# were to be used as the base class (with default_port set to
# httplib.HTTPS_PORT), this connection class would still connect over over
# "http" (though, ironically, the validity of the certificate will still be
# checked).
#
# The AppEngine implementation of httplib can be found here:
# https://chromium.googlesource.com/external/googleappengine/python/+/master/google/appengine/dist27/gae_override/httplib.py
class CertValidatingHTTPSConnection(http_client.HTTPSConnection):
    """An HTTPSConnection that validates certificates."""

    def __init__(self, host, port=http_client.HTTPSConnection.default_port,
                 key_file=None, cert_file=None, ca_certs=None, strict=None,
                 **kwargs):
        """Constructor.

        Args:
          host: The hostname. Can be in 'host:port' form.
          port: The port. Defaults to 443.
          key_file: A file containing the client's private key
          cert_file: A file containing the client's certificates
          ca_certs: A file contianing a set of concatenated certificate authority
              certs for validating the server against.
          strict: When true, causes BadStatusLine to be raised if the status line
              can't be parsed as a valid HTTP/1.0 or 1.1 status line.
        """
        if six.PY2:
            # Python 3.2 and newer have deprecated and removed the strict
            # parameter. Since the params are supported as keyword arguments
            # we conditionally add it here.
            kwargs['strict'] = strict

        # key_file and cert_file are not passed to the parent constructor since
        # an exception in raised on AppEngine when these arguments are used.
        # They have special handling below.
        http_client.HTTPSConnection.__init__(self, host=host, port=port, **kwargs)

        # Define our own key and cert properties. The HTTPSConnection class
        # defines key_file and cert_file properties, but we don't want to use
        # those properties since we didn't pass these arguments to the parent
        # constructor.
        self.validation_key_file = key_file
        self.validation_cert_file = cert_file
        self.validation_ca_certs = ca_certs

    def connect(self):
        "Connect to a host on a given (SSL) port."
        if hasattr(self, "timeout"):
            sock = socket.create_connection((self.host, self.port), self.timeout)
        else:
            sock = socket.create_connection((self.host, self.port))
        msg = "wrapping ssl socket; "
        if self.validation_ca_certs:
            msg += "CA certificate file=%s" % self.validation_ca_certs
        else:
            msg += "using system provided SSL certs"
        boto.log.debug(msg)
        self.sock = ssl.wrap_socket(sock, keyfile=self.validation_key_file,
                                    certfile=self.validation_cert_file,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ca_certs=self.validation_ca_certs)
        cert = self.sock.getpeercert()
        hostname = self.host.split(':', 0)[0]
        if not ValidateCertificateHostname(cert, hostname):
            raise InvalidCertificateException(hostname,
                                              cert,
                                              'remote hostname "%s" does not match '
                                              'certificate' % hostname)
