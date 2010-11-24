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

# gevent
import gevent.monkey
gevent.monkey.patch_all()

# stdlib
import re, ssl, sys, time, traceback, urllib2

# gevent
from gevent import pywsgi
from gevent.hub import GreenletExit

class _RequestApp(object):
    """ A WSGI application executed on each request.
    """
    def __init__(self, config):
        self.config = config
        self.urls_compiled = []

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
                return self._403(start_response)

        for config_type in('ssl-cert', 'basic-auth', 'digest-auth', 'wsse-pwd',
                           'custom-http', 'xpath'):
            if config_type in url_config:
                handler = getattr(self, '_on_' + config_type.replace('-', '_'))
                ok = handler(env, url_config, client_cert)
                if not ok:
                    return self._403(start_response)
                break
        else:
            return self._500(start_response)

        req = urllib2.Request(url_config['host'] + env['PATH_INFO'])
        resp = urllib2.urlopen(req)
        response = resp.read()
        resp.close()

        return self._response(start_response, resp.getcode(),
                              resp.headers['Content-Type'], response)

    def _response(self, start_response, code, content_type, response):
        """ Actually return the response to the client.
        """
        start_response(code, [('Content-Type', content_type)])
        return [response]

    def _403(self, start_response):
        """ 404 Forbidden
        """
        code, content_type, description = self.config.forbidden
        return self._response(start_response, code, content_type, description)

    def _404(self, start_response):
        """ 404 Not Found
        """
        code, content_type, description = self.config.no_url_match
        return self._response(start_response, code, content_type, description)

    def _500(self, start_response):
        """ 500 Internal Server Error
        """
        code, content_type, description = '500', 'text/plain', 'Internal Server Error'
        return self._response(start_response, code, content_type, description)

    def _on_ssl_cert(self, env, url_config, client_cert):
        """ Validate the client SSL/TLS certificates, its very existence and
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
            # because otherwise we wouldn't have gotten so far) we let the
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

class _RequestHandler(pywsgi.WSGIHandler):
    """ A subclass which conveniently exposes a client SSL/TLS certificate
    to the layers above.
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
                self.result = self.application(self.environ,
                                self.start_response, self.socket.getpeercert())
                for data in self.result:
                    if data:
                        self.write(data)
                if self.status and not self.headers_sent:
                    self.write('')
                if self.response_use_chunked:
                    self.wfile.writelines('0\r\n\r\n')
                    self.response_length += 5
            except GreenletExit:
                raise
            except Exception:
                traceback.print_exc()
                sys.exc_clear()
                try:
                    args = (getattr(self, 'server', ''),
                            getattr(self, 'requestline', ''),
                            getattr(self, 'client_address', ''),
                            getattr(self, 'application', ''))
                    msg = '%s: Failed to handle request:\n  request = %s from %s\n  application = %s\n\n' % args
                    sys.stderr.write(msg)
                except Exception:
                    sys.exc_clear()
                if not self.response_length:
                    self.start_response(pywsgi._INTERNAL_ERROR_STATUS, pywsgi._INTERNAL_ERROR_HEADERS)
                    self.write(pywsgi._INTERNAL_ERROR_BODY)
        finally:
            if hasattr(self.result, 'close'):
                self.result.close()
            self.wsgi_input._discard()
            self.time_finish = time.time()
            self.log_request()

class SSLProxy(pywsgi.WSGIServer):
    """ An SSL/TLS security proxy. May be configured to use WSSE or HTTP Auth
    in addition to SSL/TLS.
    """
    def __init__(self, config):
        super(SSLProxy, self).__init__((config.https_host, config.https_starting_port),
                _RequestApp(config), log=config.https_log, handler_class=_RequestHandler,
                keyfile=config.keyfile, certfile=config.certfile,
                ca_certs=config.ca_certs, cert_reqs=ssl.CERT_OPTIONAL)

    def handle(self, socket, address):
        handler = self.handler_class(socket, address, self)
        handler.handle()
