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
from contextlib import nested
import os, tempfile, shutil, subprocess, unittest, uuid

# nose
from nose.tools import assert_true, eq_

# textfixtures
from testfixtures import Replacer

# mock
from mock import Mock, mocksignature, patch

# Spring Python
from springpython.context import ApplicationContext

# sec-wall
from secwall import app_context, cli

class CLITestCase(unittest.TestCase):

    def setUp(self):
        self.app_ctx = ApplicationContext(app_context.SecWallContext())
        self.test_dir = tempfile.mkdtemp(prefix='tmp-sec-wall-')
        open(os.path.join(self.test_dir, '.sec-wall-config'), 'w')
        open(os.path.join(self.test_dir, 'config.py'), 'w')

        open(os.path.join(self.test_dir, 'zdaemon.conf'), 'w')

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_command(self):
        try:
            cli._Command(uuid.uuid4().hex, self.app_ctx, False)
        except SystemExit, e:
            eq_(e.code, 3)
        else:
            raise Exception('Expected a SystemExit here')

        expected_pid = uuid.uuid4().int

        with patch.object(cli._Command, '_execute_zdaemon_command') as mock_method:

            # Any command other than 'stop'. Should simply return the pid
            # of the subprocess.
            command_name = uuid.uuid4().hex
            mock_method.return_value = expected_pid
            command = cli._Command(self.test_dir, self.app_ctx, False)
            given_pid = command._zdaemon_command(command_name, 'foo.conf')

            eq_(expected_pid, given_pid)
            eq_(mock_method.called, True)
            mock_method.assert_called_with(
                [u'zdaemon', u'-C', os.path.join(self.test_dir, 'foo.conf'), command_name])

            # The 'stop' command. Not only does it communicate with
            # the subprocesses but also deleted the zdaemon's config file
            # created in the self.setUp method.
            command._zdaemon_command('stop', 'zdaemon.conf')

            exists = os.path.exists(os.path.join(self.test_dir, 'zdaemon.conf'))
            eq_(exists, False)

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
