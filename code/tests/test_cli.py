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
import glob, imp, os, tempfile, shutil, subprocess, unittest, uuid

# nose
from nose.tools import assert_raises, assert_true, eq_

# textfixtures
from testfixtures import Replacer

# mock
from mock import Mock, mocksignature, patch

# Spring Python
from springpython.context import ApplicationContext

# sec-wall
from secwall import app_context, cli

class _BaseTestCase(unittest.TestCase):
    """ A base class for all CLI-related test cases.
    """
    temp_dir_prefix = 'tmp-sec-wall-'

    def tearDown(self):
        temp_dir = tempfile.gettempdir()
        pattern = os.path.join(temp_dir, self.temp_dir_prefix) + '*'
        temp_dirs = glob.glob(pattern)

        for temp_dir in temp_dirs:
            shutil.rmtree(temp_dir)

class CommandTestCase(_BaseTestCase):
    """ Tests for the secwall.cli._Command class.
    """

    def setUp(self):
        self.app_ctx = ApplicationContext(app_context.SecWallContext())
        self.test_dir = tempfile.mkdtemp(prefix=self.temp_dir_prefix)
        open(os.path.join(self.test_dir, '.sec-wall-config'), 'w')
        open(os.path.join(self.test_dir, 'config.py'), 'w')
        open(os.path.join(self.test_dir, 'zdaemon.conf'), 'w')

    def test_defaults(self):
        """ Tests the correct values of the default class-level objects.
        """
        eq_(cli._Command.needs_config_mod, True)
        eq_(cli._Command._config_marker, '.sec-wall-config')

    def test_command_init(self):
        """ Tests the cli._Command.__init__ method.
        """
        try:
            cli._Command(uuid.uuid4().hex, self.app_ctx, False)
        except SystemExit, e:
            eq_(e.code, 3)
        else:
            raise Exception('Expected a SystemExit here')

    def test_command_not_stop(self):
        """ Tests whether executing a command other that 'stop' returns the
        process' PID.
        """

        expected_pid = uuid.uuid4().int

        with patch.object(cli._Command, '_execute_zdaemon_command') as mock_method:

            # Any command other than 'stop'. Should simply return the pid
            # of the subprocess.
            command_name = uuid.uuid4().hex
            mock_method.return_value = expected_pid
            command = cli._Command(self.test_dir, self.app_ctx, False)
            given_pid = command._zdaemon_command(command_name, 'foo.conf')

            eq_(given_pid, expected_pid)
            eq_(mock_method.called, True)
            mock_method.assert_called_with(
                [u'zdaemon', u'-C', os.path.join(self.test_dir, 'foo.conf'), command_name])

    def test_command_stop(self):
        """ Tests whether executing a 'stop' command deletes a temporary zdaemon's
        config file.
        """
        expected_pid = uuid.uuid4().int

        with patch.object(cli._Command, '_execute_zdaemon_command') as mock_method:

            # The 'stop' command. Not only does it communicate with
            # the subprocesses but also deleted the zdaemon's config file
            # created in the self.setUp method.
            command = cli._Command(self.test_dir, self.app_ctx, False)
            command._zdaemon_command('stop', 'zdaemon.conf')

            exists = os.path.exists(os.path.join(self.test_dir, 'zdaemon.conf'))
            eq_(exists, False)

    def test_wait_none(self):
        """ Tests whether an Exception is being raised when the return value
        of the .wait call is None.
        """

        # The return code of the 'wait' call on a Popen object returned None.
        # Doesn't even matter that there were too few arguments in the call
        # to 'zdaemon' command as we hadn't even got as far as to actually call
        # it.
        with Replacer() as r:
            def _wait(self):
                self.returncode = None

            r.replace('subprocess.Popen.wait', _wait)

            try:
                command = cli._Command(self.test_dir, self.app_ctx, False)
                command._execute_zdaemon_command(['zdaemon'])
            except Exception, e:
                eq_(e.args[0], 'Could not execute command [u\'zdaemon\'] (p.returncode is None)')
            else:
                raise Exception('An exception was expected here.')

    def test_too_few_arguments(self):
        """ Tests the expected exception and the return code when there are
        too few arguments passed in to 'zdaemon' command.
        """

        # Too few arguments to the 'zdaemon' command.
        with Replacer() as r:
            stdout = uuid.uuid4().hex
            stderr = uuid.uuid4().hex

            def _communicate(self):
                return [stdout, stderr]

            r.replace('subprocess.Popen.communicate', _communicate)

            try:
                command = cli._Command(self.test_dir, self.app_ctx, False)
                command._execute_zdaemon_command(['zdaemon'])
            except Exception, e:
                msg = e.args[0]
                expected_start = 'Failed to execute command [u\'zdaemon\']. return code=['
                expected_end = '], stdout=[{0}], stderr=[{1}]'.format(stdout, stderr)
                assert_true(msg.startswith(expected_start))
                assert_true(msg.endswith(expected_end))

                return_code = msg[len(expected_start):-len(expected_end)]

                # We caught an error so the return_code must be a positive integer.
                return_code = int(return_code)
                assert_true(return_code > 0)

            else:
                raise Exception('An exception was expected here.')

    def test_pid_returning(self):
        """ Tests whether the correct PID is being returned by the
        '_execute_zdaemon_command' method.
        """

        with Replacer() as r:

            expected_pid = 4893
            stdout = 'program running; pid={0}'.format(expected_pid)
            stderr = uuid.uuid4().hex

            def _communicate(self):
                return [stdout, stderr]

            def _Popen(self, *ignored_args, **ignored_kwargs):
                class _DummyPopen(object):
                    def __init__(self, *ignored_args, **ignored_kwargs):
                        self.returncode = 0

                    def communicate(self):
                        return stdout, stderr

                    def wait(self):
                        pass

                return _DummyPopen()

            r.replace('subprocess.Popen', _Popen)

            command = cli._Command(self.test_dir, self.app_ctx, False)
            given_pid = int(command._execute_zdaemon_command(['zdaemon']))

            # PIDs must be the same.
            eq_(given_pid, expected_pid)

    def test_enrichment(self):
        """ Tests whether enrichment of the config module works fine.
        """
        command = cli._Command(self.test_dir, self.app_ctx, False)
        config_mod = command._get_config_mod()
        elems = [elem for elem in dir(config_mod) if not elem.startswith('__')]
        eq_(len(elems), 18)

        names = ('server_type', 'host', 'port', 'log', 'crypto_dir', 'keyfile',
                 'certfile', 'ca_certs', 'not_authorized', 'forbidden',
                 'no_url_match', 'validation_precedence', 'client_cert_401_www_auth',
                 'syslog_host', 'syslog_port', 'syslog_facility',
                 'syslog_level', 'server_tag')
        for name in names:
            assert_true(name in elems)

    def test_run_not_implemented_error(self):
        """ Tests whether the default implementation of the .run method raises
        a NotImplementedError.
        """

        # The 'run' method must be implemented by subclasses.
        command = cli._Command(self.test_dir, self.app_ctx, False)
        assert_raises(NotImplementedError, command.run)

class InitTestCase(_BaseTestCase):
    """ Tests for the secwall.cli.Init class.
    """

    def setUp(self):
        self.app_ctx = ApplicationContext(app_context.SecWallContext())
        self.test_dir = tempfile.mkdtemp(prefix='tmp-sec-wall-')

    def test_defaults(self):
        """ Tests the class-level defaults.
        """
        eq_(cli.Init.needs_config_mod, False)

    def test_run_dir_non_empty(self):
        """ Running the command in a non-empty dir should result in an
        exception being raised.
        """
        open(os.path.join(self.test_dir, uuid.uuid4().hex), 'w').close()
        init = cli.Init(self.test_dir, self.app_ctx, False)
        try:
            init.run()
        except SystemExit, e:
            return_code = e.args[0]
            eq_(int(return_code), 3)
        else:
            raise Exception('Expected a SystemExit here')

    def test_run_dir_empty(self):
        """ Simulates the actual user's executing the command in an empty
        directory and tests whether the files created by the command are fine.
        """
        init = cli.Init(self.test_dir, self.app_ctx, False)
        init.run()

        f, p, d = imp.find_module('config', [self.test_dir])
        config_mod = imp.load_module('config', f, p, d)

        instance_secret = getattr(config_mod, 'INSTANCE_SECRET')
        cur_dir = getattr(config_mod, 'cur_dir')
        keyfile = getattr(config_mod, 'keyfile')
        certfile = getattr(config_mod, 'certfile')
        ca_certs = getattr(config_mod, 'ca_certs')
        default_handler = getattr(config_mod, 'default')
        urls = getattr(config_mod, 'urls')

        # Instance secret is a UUID4 by default
        eq_(len(instance_secret), 32)
        eq_(uuid.UUID(instance_secret, version=4).hex, instance_secret)

        eq_(cur_dir, self.test_dir)
        eq_(os.path.normpath(keyfile), os.path.join(self.test_dir, 'crypto', 'server-priv.pem'))
        eq_(os.path.normpath(certfile), os.path.join(self.test_dir, 'crypto', 'server-cert.pem'))
        eq_(os.path.normpath(ca_certs), os.path.join(self.test_dir, 'crypto', 'ca-cert.pem'))

        default_config = default_handler()
        eq_(len(default_config), 4)
        eq_(default_config['ssl'], True)
        eq_(default_config['ssl-cert'], True)
        eq_(default_config['ssl-cert-commonName'], instance_secret)
        eq_(default_config['host'], 'http://' + instance_secret)

        eq_(urls, [('/*', default_config),])
