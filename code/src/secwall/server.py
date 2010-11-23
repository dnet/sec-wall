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

    def __call__(self, env, start_response, peer_cert=None):
        """ Executed on each request. Checks whether URL has been invoked yet,
        reads the config if it has and passes the control on to the main request
        handler. In case no config for the given URL is found, a 404 Not Found
        will be returned to the calling side.
        """

        for c, url_config in self.urls_compiled:
            match = c.match(env['PATH_INFO'])
            if match:
                return self._on_request(start_response, env['PATH_INFO'], url_config, peer_cert)
        else:
            # No config for that URL, we can't let the client in.
            return self._404(start_response)

    def _on_request(self, start_response, path_info, url_config, peer_cert):
        """ Checks security, invokes the backend server, returns the response.
        """

        if url_config.get('cert-needed'):
            if not peer_cert:
                return self._403(start_response)

        req = urllib2.Request(url_config['host'] + path_info)
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

    def _404(self, start_response):
        """ 404 Not Found
        """
        code, content_type, description = self.config.no_url_match
        return self._response(start_response, code, content_type, description)

    def _403(self, start_response):
        """ 404 Forbidden
        """
        code, content_type, description = self.config.forbidden
        return self._response(start_response, code, content_type, description)

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
                _RequestApp(config), log=config.https_log,
                keyfile=config.keyfile, certfile=config.certfile,
                ca_certs=config.ca_certs, cert_reqs=ssl.CERT_OPTIONAL)

    def handle(self, socket, address):
        handler = self.handler_class(socket, address, self)
        handler.handle()
