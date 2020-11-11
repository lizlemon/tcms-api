# pylint: disable=too-few-public-methods

import urllib.parse

from base64 import b64encode
from http import HTTPStatus
from http.client import HTTPSConnection
from xmlrpc.client import SafeTransport, Transport, ServerProxy

import ssl
try:
    import gssapi
except ImportError:
    gssapi = None

import requests

from tcms_api.version import __version__


VERBOSE = 0


class CookieTransport(Transport):
    """A subclass of xmlrpc.client.Transport that supports cookies."""
    scheme = 'http'
    user_agent = 'tcms-api/%s' % __version__

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cookies = []

    def send_headers(self, connection, headers):
        if self._cookies:
            connection.putheader("Cookie", "; ".join(self._cookies))
        super().send_headers(connection, headers)

    def parse_response(self, response):
        for header in response.msg.get_all("Set-Cookie", []):
            cookie = header.split(";", 1)[0]
            self._cookies.append(cookie)
        return super().parse_response(response)


class SafeCookieTransport(SafeTransport):
    """A SafeTransport (HTTPS) subclass that retains cookies over its lifetime."""
    user_agent = 'tcms-api/%s' % __version__

    # found this code here:
    # https://stackoverflow.com/questions/25876503/how-to-retain-cookies-for-xmlrpc-client-in-python-3/47291771
    # Note context option - it's required for success
    def __init__(self, context=None, *args, **kwargs):
        super().__init__(context=context, *args, **kwargs)
        self._cookies = []

    def send_headers(self, connection, headers):
        if self._cookies:
            connection.putheader("Cookie", "; ".join(self._cookies))
        super().send_headers(connection, headers)

    def parse_response(self, response):
        # This check is required if in some responses we receive no cookies at all
        if response.msg.get_all("Set-Cookie"):
            for header in response.msg.get_all("Set-Cookie"):
                cookie = header.split(";", 1)[0]
                self._cookies.append(cookie)
        return super().parse_response(response)


class KerbTransport(SafeCookieTransport):
    """Handles GSSAPI Negotiation (SPNEGO) authentication."""

    def get_host_info(self, host):
        host, extra_headers, x509 = Transport.get_host_info(self, host)

        # Set the remote host principal
        hostinfo = host.split(':')
        service = "HTTP@" + hostinfo[0]

        service_name = gssapi.Name(service, gssapi.NameType.hostbased_service)
        context = gssapi.SecurityContext(usage="initiate", name=service_name)
        token = context.step()

        extra_headers = [
            ("Authorization", "Negotiate %s" % b64encode(token).decode())
        ]

        return host, extra_headers, x509

    def make_connection(self, host):
        """
            Return an individual HTTPS connection for each request.

            Fix https://bugzilla.redhat.com/show_bug.cgi?id=735937
        """
        chost, self._extra_headers, x509 = self.get_host_info(host)
        # Kiwi TCMS isn't ready to use HTTP/1.1 persistent connections,
        # so tell server current opened HTTP connection should be closed after
        # request is handled. And there will be a new connection for the next
        # request.
        self._extra_headers.append(('Connection', 'close'))
        self._connection = host, HTTPSConnection(  # nosec:B309:blacklist
            chost,
            None,
            **(x509 or {})
        )
        return self._connection[1]


def get_hostname(url):
    """
        Performs the same parsing of the URL as the Transport
        class and returns only the hostname which is used to
        generate the service principal name for Kiwi TCMS and
        the respective Authorize header!
    """
    _type, uri = urllib.parse.splittype(url)
    hostname, _path = urllib.parse.splithost(uri)
    return hostname


class TCMSXmlrpc:
    """
        XML-RPC client for username/password authentication.
    """
    session_cookie_name = 'sessionid'

    def __init__(self, username, password, url, verify=True):
        server_args = {"verbose": VERBOSE, "allow_none": 1}
        if url.startswith('https://'):
            if verify:
                server_args["transport"] = SafeCookieTransport()
            else:
                context = ssl._create_unverified_context()
                server_args["transport"] = SafeCookieTransport(context)
                server_args["context"] = context
        elif url.startswith('http://'):
            server_args["transport"] = CookieTransport()
        else:
            raise Exception("Unrecognized URL scheme")

        self.server = ServerProxy(url, **server_args)
        self.login(username, password, url)

    def login(
            self, username, password, url):  # pylint: disable=unused-argument
        """
            Login in the web app to save a session cookie in the cookie jar!
        """
        self.server.Auth.login(username, password)


class TCMSKerbXmlrpc(TCMSXmlrpc):
    """
        XML-RPC client for server deployed with python-social-auth-kerberos.

        Should also work for servers deployed with mod_auth_gssapi but
        that is not supported nor guaranteed!
    """
    transport = KerbTransport()

    def __init__(self, username, password, url):
        if not url.startswith('https://'):
            raise Exception("https:// required for GSSAPI authentication."
                            "URL provided: %s" % url)

        if gssapi is None:
            raise RuntimeError("gssapi not found! "
                               "Try pip install tcms-api[gssapi]")

        super().__init__(username, password, url)

    def login(self, username, password, url):
        url = url.replace('xml-rpc', 'login/kerberos')
        hostname = get_hostname(url)

        _, headers, _ = self.transport.get_host_info(hostname)
        # transport returns list of tuples but requests needs a dictionary
        headers = dict(headers)
        headers['User-Agent'] = self.transport.user_agent

        # note: by default will follow redirects
        with requests.sessions.Session() as session:
            response = session.get(url, headers=headers)
            assert response.status_code == HTTPStatus.OK
            self.transport._cookies.append(  # pylint: disable=protected-access
                self.session_cookie_name + '=' +
                session.cookies[self.session_cookie_name]
            )
