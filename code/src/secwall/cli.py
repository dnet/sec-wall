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
import imp, os, subprocess, sys

# sec-wall
from secwall.server import Proxy

class _Command(object):
    """ A base class for all CLI commands.
    """

    # Most of the commands need direct access to the configuration module,
    # thus if 'needs_config_mod' is not False, the config will be read in
    # the command's __init__ method.
    needs_config_mod = True

    # A directory containing a file of that name will be considered to
    # be a sec-wall's config directory.
    _config_marker = '.sec-wall-config'

    def __init__(self, config_dir, app_ctx, bind_port, is_https):
        config_dir = os.path.abspath(config_dir)
        if not os.path.exists(config_dir):
            msg = "Path {0} doesn't exist.\n".format(config_dir)
            self._error(msg)

        self.config_dir = config_dir
        self.app_ctx = app_ctx
        self.bind_port = int(bind_port) if bind_port else None
        self.is_https = True if is_https and int(is_https) else False

        if self.needs_config_mod:
            self.config_mod = self._get_config_mod()

    def _zdaemon_command(self, zdaemon_command, conf_file):
        """ A somewhat higher-level wrapper for executing zdaemon's commands.
        """

        conf_file = os.path.abspath(os.path.join(self.config_dir, conf_file))

        port = conf_file.split('zdaemon-')[1].split('.conf')[0]
        pid = self._execute_zdaemon_command(['zdaemon', '-C', conf_file, zdaemon_command])

        if zdaemon_command == 'stop':
            os.remove(conf_file)

        return port, pid

    def _execute_zdaemon_command(self, command_list):
        """ A low-level wrapper for executing zdaemon's commands through
        subprocesses and pipes (doesn't talk directly to the zdaemon's socket).
        """
        p = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()

        if p.returncode is None:
            msg = 'Could not execute command {0} (p.returncode is None)'
            msg = msg.format(command)
            raise Exception(msg)

        else:
            if p.returncode != 0:
                stdout, stderr = p.communicate()
                msg = 'Failed to execute command {0}.'
                msg += ' return code=[{1}], stdout=[{2}], stderr=[{3}]'
                msg = msg.format(command, p.returncode, stdout, stderr)
                raise Exception(msg)

            stdout, stderr = p.communicate()
            if stdout.startswith('program running'):
                data = stdout
                data = data.split(';')[1].strip()
                pid = data.split('=')[1].strip()

                return pid

    def _get_config_mod(self):
        """ Return a fully initialized, ready to use, config module. Any missing
        values are filled in with defaults from the app context.
        """

        marker_path = os.path.normpath(os.path.join(self.config_dir, self._config_marker))
        if not os.path.exists(marker_path):
            msg = "{0} file is missing,".format(self._config_marker)
            msg += " are you sure {0} is a sec-wall's".format(self.config_dir)
            msg += ' config directory?\n'
            self._error(msg)

        f, p, d = imp.find_module('config', [self.config_dir])
        config_mod = imp.load_module('config', f, p, d)

        names = ('http_subproc_number', 'https_subproc_number', 'start_http',
                 'start_https', 'http_host', 'https_host',
                 'http_starting_port', 'https_starting_port', 'http_log',
                 'https_log', 'crypto_dir', 'keyfile', 'certfile', 'ca_certs',
                 'not_authorized', 'forbidden', 'no_url_match',
                 'validation_precedence', 'client_cert_401_www_auth',
                 'syslog_host', 'syslog_port', 'syslog_facility',
                 'syslog_level', 'server_tag')

        for name in names:
            attr = getattr(config_mod, name, None)
            if not attr:
                attr = self.app_ctx.get_object(name)
                setattr(config_mod, name, attr)

        return config_mod

    def _error(self, msg, use_prefix=True):
        """ A utility method for printing the error message and quiting the app.
        """
        if use_prefix:
            msg = "Couldn't start sec-wall. " + msg

        sys.stderr.write(msg)
        sys.exit(3)

    def run(self):
        """ Must be overridden in subclasses.
        """
        raise NotImplementedError()

class Init(_Command):
    """ Handles the 'sec-wall --init /path/to/config/dir' command.
    """
    needs_config_mod = False

    def run(self):
        listing = os.listdir(self.config_dir)
        if listing:
            msg = '{0} is not empty. Please re-run the command in an empty directory.\n'
            msg = msg.format(self.config_dir)
            self._error(msg, False)

        config_py_template = self.app_ctx.get_object('config_py_template')
        haproxy_conf_template = self.app_ctx.get_object('haproxy_conf_template')

        open(os.path.join(self.config_dir, 'config.py'), 'w').write(config_py_template)
        open(os.path.join(self.config_dir, 'haproxy.conf-template'), 'w').write(haproxy_conf_template)
        os.mkdir(os.path.join(self.config_dir, 'logs'))

        open(os.path.join(self.config_dir, self._config_marker), 'w').close()

class Start(_Command):
    """ Handles the 'sec-wall --start /path/to/config/dir' command.
    """
    def run(self):
        missing = []
        if self.config_mod.start_https:
            for name in('keyfile', 'certfile', 'ca_certs'):
                path = getattr(self.config_mod, name)
                path = os.path.normpath(path)
                if not os.path.exists(path):
                    missing.append(path)

        if missing:
            noun, verb = ('file', 'exists') if len(missing) == 1 else \
                ('files', 'exist')

            msg = "Either set 'start_https' to False"
            msg += ' in {0}'.format(os.path.join(self.config_dir, 'config.py'))
            msg += ' or make sure the following {0} {1}:\n'.format(noun, verb)

            for path in missing:
                msg += '  * {0}\n'.format(path)

            self._error(msg)
        else:
            ports = []

            if not any((self.config_mod.start_http, self.config_mod.start_https)):
                msg = "Config is not valid, make sure at least one of 'start_http'"
                msg += " or 'start_https' options is True.\n"
                self._error(msg)

            if self.config_mod.start_http:
                if not self.config_mod.http_subproc_number >= 1:
                    msg = "'start_http' is True - make sure 'http_subproc_number' is a"
                    msg += ' positive integer.\n'
                    self._error(msg)
                else:
                    start = self.config_mod.http_starting_port
                    stop = start + self.config_mod.http_subproc_number
                    ports.append([start, stop, 0]) # is_https -> boolean False

            if self.config_mod.start_https:
                if not self.config_mod.https_subproc_number >= 1:
                    msg = "'start_https' is True - make sure 'https_subproc_number' is a"
                    msg += ' positive integer.\n'
                    self._error(msg)
                else:
                    start = self.config_mod.https_starting_port
                    stop = start + self.config_mod.https_subproc_number
                    ports.append([start, stop, 1]) # is_https -> boolean True

            for start, stop, is_https in ports:
                for port in range(start, stop):
                    zdaemon_conf = self.app_ctx.get_object('zdaemon_conf_template')
                    zdaemon_conf = zdaemon_conf.format(config_dir=self.config_dir,
                                                       port=port, is_https=is_https)
                    zdaemon_conf_file = os.path.join(self.config_dir, 'zdaemon-{0}.conf'.format(port))
                    open(zdaemon_conf_file, 'w').write(zdaemon_conf)

                    self._zdaemon_command('start', zdaemon_conf_file)

class Fork(_Command):
    """ Handles the 'sec-wall --fork /path/to/config/dir port is_https' command.
    """
    def run(self):
        proxy = Proxy(self.config_mod, self.bind_port, self.is_https)
        proxy.serve_forever()

class Stop(_Command):
    """ Handles the 'sec-wall --stop /path/to/config/dir' command.
    """
