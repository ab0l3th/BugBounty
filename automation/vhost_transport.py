from __future__ import annotations

import http.client
import ipaddress
import re
from urllib import error, request
from urllib.parse import urlsplit


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, *, connect_ip, **kwargs):
        super().__init__(host, **kwargs)
        original = self._create_connection
        self._create_connection = lambda address, *args, **options: original((connect_ip, address[1]), *args, **options)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, *, connect_ip, **kwargs):
        super().__init__(host, **kwargs)
        original = self._create_connection
        self._create_connection = lambda address, *args, **options: original((connect_ip, address[1]), *args, **options)


def vhost_request(hostname, address, *, scheme='https', path='/'):
    ipaddress.ip_address(address)
    if scheme not in {'https', 'http'} or not hostname or any(char in hostname for char in '/\\:@ \r\n'):
        raise ValueError('Invalid vhost route')
    req = request.Request(f'{scheme}://{hostname}{path}', headers={'Host': hostname, 'User-Agent': 'BugBountyScopeCheck/1.0'}, method='GET')
    req._vhost_connect_ip = address
    return req


def _pinned_origin(req):
    address = getattr(req, '_vhost_connect_ip', None)
    if not address:
        return None
    ipaddress.ip_address(address)
    if req.has_proxy() or getattr(req, '_tunnel_host', None):
        raise error.URLError('Proxy transport cannot preserve pinned vhost origin; probe skipped')
    parsed = urlsplit(req.full_url)
    if not parsed.hostname or req.get_header('Host') != parsed.hostname:
        raise error.URLError('Vhost hostname, Host header, and TLS identity must match')
    return address


class VhostHTTPHandler(request.HTTPHandler):
    def http_open(self, req):
        address = _pinned_origin(req)
        if address is None:
            return super().http_open(req)
        return self.do_open(lambda host, **kwargs: PinnedHTTPConnection(host, connect_ip=address, **kwargs), req)


class VhostHTTPSHandler(request.HTTPSHandler):
    def https_open(self, req):
        address = _pinned_origin(req)
        if address is None:
            return super().https_open(req)
        return self.do_open(lambda host, **kwargs: PinnedHTTPSConnection(host, connect_ip=address, **kwargs),
                            req, context=self._context)


class VhostRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, response, code, message, headers, destination):
        previous = urlsplit(req.full_url)
        target = urlsplit(destination)
        count = getattr(req, '_vhost_redirect_count', 0) + 1
        login = re.search(r'(?:^|[./_-])(?:login|signin|sign-in|sso|oauth|auth|authorize|accounts?)(?:[./_-]|$)', target.path, re.IGNORECASE)
        if target.hostname != previous.hostname or login or count > 3 or previous.scheme == 'https' and target.scheme != 'https':
            raise error.URLError('Vhost redirect left the approved origin or reached a login/downgrade path')
        redirected = super().redirect_request(req, response, code, message, headers, destination)
        if redirected is not None:
            redirected._vhost_redirect_count = count
            if getattr(req, '_vhost_connect_ip', None):
                redirected._vhost_connect_ip = req._vhost_connect_ip
        return redirected


def vhost_opener(*handlers):
    redirects = [] if any(isinstance(handler, request.HTTPRedirectHandler) for handler in handlers) else [VhostRedirectHandler()]
    return request.build_opener(VhostHTTPHandler(), VhostHTTPSHandler(), *redirects, *handlers)