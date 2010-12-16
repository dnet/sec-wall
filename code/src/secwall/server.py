# -*- coding: utf-8 -*-

"""
Copyright (C) 2010 Dariusz Suchojad <dsuch at gefira.pl>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

# stdlib
import re, ssl, sys, time, traceback, urllib2

# lxml
from lxml import etree

# gevent
from gevent import pywsgi, wsgi
from gevent.hub import GreenletExit

# sec-wall
from secwall import wsse
from secwall.core import SecurityException

class _RequestApp(object):
    """ A WSGI application executed on each request.
    """
    def __init__(self, config=None, app_ctx=None):
        self.config = config
        self.urls_compiled = []
        self.app_ctx = app_ctx
        self.wsse = self.app_ctx.get_object('wsse')

        for url_pattern, url_config in self.config.urls:
            self.urls_compiled.append((re.compile(url_pattern), url_config))

    def __call__(self, env, start_response, client_cert=None):
        """ Finds the configuration for the given URL and passes the control on
        to the main request handler. In case no config for the given URL is
        found, a 404 Not Found will be returned to the calling side.
        """
        for c, url_config in self.urls_compiled:
            match = c.match(env['PATH_INFO'])
            if match:
                return self._on_request(start_response, env, url_config, client_cert)
        else:
            # No config for that URL, we can't let the client in.
            return self._404(start_response)

    def _on_request(self, start_response, env, url_config, client_cert):
        """ Checks security, invokes the backend server, returns the response.
        """

        # Some quick SSL-related checks first.
        if url_config.get('ssl'):

            # Has the URL been accessed through SSL/TLS?
            if env.get('wsgi.url_scheme') != 'https':
                return self._403(start_response)

            # Is the client cert required?
            if url_config.get('ssl-cert') and not client_cert:
                return self._401(start_response, self._get_www_auth(url_config, 'ssl-cert'))

        data = env['wsgi.input'].read()

        for config_type in self.config.validation_precedence:
            if config_type in url_config:
                handler = getattr(self, '_on_' + config_type.replace('-', '_'))
                ok = handler(env, url_config, client_cert, data)
                if not ok:
                    www_auth = self._get_www_auth(url_config, config_type)
                    return self._401(start_response, www_auth)
                break
        else:
            return self._500(start_response)

        req = urllib2.Request(url_config['host'] + env['PATH_INFO'], data)
        try:
            resp = urllib2.urlopen(req)
        except urllib2.HTTPError, e:
            resp = e

        response = resp.read()
        resp.close()

        code_status = '{0} {1}'.format(resp.getcode(), resp.msg)

        return self._response(start_response, code_status,
                              [('Content-Type', resp.headers['Content-Type'])],
                              response)

    def _get_www_auth(self, url_config, config_type):
        """ Returns a value of the WWW-Authenticate header to use upon a 401 error.
        """
        www_auth = {
            'ssl-cert': self.config.client_cert_401_www_auth,
            'basic-auth': 'Basic realm="{realm}"',
            'digest-auth': 'TODO',
            'wsse-pwd': 'WSSE realm="{realm}", profile="UsernameToken"',
            'custom-http': 'custom-http',
            'xpath': 'xpath'
        }
        header_value = www_auth[config_type]

        if config_type in('basic-auth', 'wsse-pwd'):
            header_value = header_value.format(realm=url_config[config_type + '-' + 'realm'])

        return header_value

    def _response(self, start_response, code_status, headers, response):
        """ Actually returns the response to the client.
        """
        start_response(code_status, headers)
        return [response]

    def _401(self, start_response, www_auth):
        """ 401 Not Authorized
        """
        code, content_type, description = self.config.not_authorized
        headers = [('Content-Type', content_type), ('WWW-Authenticate', www_auth)]

        return self._response(start_response, code, headers, description)

    def _403(self, start_response):
        """ 403 Forbidden
        """
        code, content_type, description = self.config.forbidden
        return self._response(start_response, code, [('Content-Type', content_type)], description)

    def _404(self, start_response):
        """ 404 Not Found
        """
        code, content_type, description = self.config.no_url_match
        return self._response(start_response, code, [('Content-Type', content_type)], description)

    def _500(self, start_response):
        """ 500 Internal Server Error
        """
        code, content_type, description = self.config.internal_server_error
        return self._response(start_response, code, [('Content-Type', content_type)], description)

    def _on_ssl_cert(self, env, url_config, client_cert, data):
        """ Validates the client SSL/TLS certificates, its very existence and
        the values of its fields (commonName, organizationName etc.)
        """
        if client_cert:
            field_prefix = 'ssl-cert-'
            config_fields = {}
            for field, value in url_config.items():
                if field.startswith(field_prefix):
                    config_fields[field.split(field_prefix)[1]] = value

            # The user just wants the connection be encrypted and the client
            # use client certificate however they're not interested in the
            # cert's fields - so as long as the CA is OK (and we know it is
            # because otherwise we wouldn't have gotten so far), we let the
            # client in.
            if not config_fields:
                return True
            else:
                subject =  client_cert.get('subject')
                if not subject:
                    return False

                cert_fields = dict(elem[0] for elem in subject)

                for config_field, config_value in config_fields.items():
                    cert_value = cert_fields.get(config_field)
                    if not cert_value:
                        return False
                    if cert_value != config_value:
                        return False
                else:
                    return True

    def _on_wsse_pwd(self, env, url_config, unused_client_cert, data):
        """ Uses WS-Security UsernameToken/Password to validate the request.
        """
        if not data:
            return False

        request = etree.fromstring(data)
        try:
            ok = self.wsse.validate(request, url_config)
        except SecurityException, e:
            return False
        else:
            return ok

    def _on_basic_auth(self, env, url_config, *ignored):
        """ Handles HTTP Basic Authentication.
        """
        auth = env.get('HTTP_AUTHORIZATION')
        if not auth:
            return False

        prefix = 'Basic '
        if not auth.startswith(prefix):
            return False

        _, auth = auth.split(prefix)
        auth = auth.strip().decode('base64')

        username, password = auth.split(':', 1)

        if username == url_config['basic-auth-username'] and \
           password == url_config['basic-auth-password']:
            return True

        return False

    def _on_digest_auth(self):
        """ Handles HTTP Digest Authentication.
        """
        raise NotImplementedError()

    def _on_custom_http(self):
        """ Handles the authentication based on custom HTTP headers.
        """
        raise NotImplementedError()

    def _on_xpath(self):
        """ Handles the authentication based on XPath expressions.
        """
        raise NotImplementedError()

class _RequestHandler(pywsgi.WSGIHandler):
    """ A subclass which conveniently exposes a client SSL/TLS certificate
    to the layers above. Note that some of the lines have been given the
    '# pragma: no cover' comment, that's because they were simply copy & pasted
    from the base class and we have no tests to cover them.
    """
    def handle_one_response(self):
        self.time_start = time.time()
        self.status = None
        self.headers_sent = False

        self.result = None
        self.response_use_chunked = False
        self.response_length = 0

        try:
            try:
                cert = self.socket.getpeercert() if hasattr(self.socket, 'getpeercert') \
                     else None
                self.result = self.application(self.environ, self.start_response, cert)
                for data in self.result:
                    if data:
                        self.write(data)
                if self.status and not self.headers_sent:
                    self.write('')                               # pragma: no cover
                if self.response_use_chunked:                    # pragma: no cover
                    self.wfile.writelines('0\r\n\r\n')           # pragma: no cover
                    self.response_length += 5                    # pragma: no cover
            except GreenletExit:                                 # pragma: no cover
                raise                                            # pragma: no cover
            except Exception:                                    # pragma: no cover
                traceback.print_exc()                            # pragma: no cover
                sys.exc_clear()                                  # pragma: no cover
                try:                                             # pragma: no cover
                    args = (getattr(self, 'server', ''),         # pragma: no cover
                            getattr(self, 'requestline', ''),    # pragma: no cover
                            getattr(self, 'client_address', ''), # pragma: no cover
                            getattr(self, 'application', ''))    # pragma: no cover
                    msg = '%s: Failed to handle request:\n  request = %s from %s\n  application = %s\n\n' % args # pragma: no cover
                    sys.stderr.write(msg)                        # pragma: no cover
                except Exception:                                # pragma: no cover
                    sys.exc_clear()                              # pragma: no cover
                if not self.response_length:                     # pragma: no cover
                    self.start_response(pywsgi._INTERNAL_ERROR_STATUS, pywsgi._INTERNAL_ERROR_HEADERS) # pragma: no cover
                    self.write(pywsgi._INTERNAL_ERROR_BODY)      # pragma: no cover
        finally:                                                 # pragma: no cover
            if hasattr(self.result, 'close'):                    # pragma: no cover
                self.result.close()                              # pragma: no cover
            self.wsgi_input._discard()
            self.time_finish = time.time()
            self.log_request()

class HTTPProxy(wsgi.WSGIServer):
    """ A plain HTTP proxy.
    """
    def __init__(self, config, app_ctx):
        wsgi_request_app = app_ctx.get_object('wsgi_request_app')

        super(HTTPProxy, self).__init__((config.host, config.port),
                wsgi_request_app(config, app_ctx), log=config.log)

class HTTPSProxy(pywsgi.WSGIServer):
    """ An SSL/TLS proxy.
    """
    def __init__(self, config, app_ctx):
        wsgi_request_app = app_ctx.get_object('wsgi_request_app')
        wsgi_request_handler = app_ctx.get_object('wsgi_request_handler')

        super(HTTPSProxy, self).__init__((config.host, config.port),
                wsgi_request_app(config, app_ctx), log=config.log,
                handler_class=wsgi_request_handler, keyfile=config.keyfile,
                certfile=config.certfile, ca_certs=config.ca_certs,
                cert_reqs=ssl.CERT_OPTIONAL)

    def handle(self, socket, address):
        handler = self.handler_class(socket, address, self)
        handler.handle()
