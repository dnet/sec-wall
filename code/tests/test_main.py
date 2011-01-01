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
import argparse, copy, tempfile, uuid

# nose
from nose.tools import assert_true, eq_

# textfixtures
from testfixtures import Replacer

# Spring Python
from springpython.context import ApplicationContext

# sec-wall
from secwall import core, main, app_context

def test_global():
    """ Checks global constants.
    """
    eq_(main.description, 'sec-wall {0}- A feature packed high-performance security proxy'.format(core.version))
    eq_(main.init_help, 'Initializes a config directory')
    eq_(main.start_help, 'Starts sec-wall in the given directory')
    eq_(main.stop_help, 'Stops a sec-wall instance running in the given directory')
    eq_(main.fork_help, 'Starts one of the sec-wall\'s subprocesses')

def test_help_formatter():
    """ Checks whether our custom help formatter works as expected.
    """
    eq_(main.MyFormatter.max_help_position, 35)

    formatter = main.MyFormatter(prog='ignored')
    help_value = uuid.uuid4().hex

    class _MyAction(object):
        help = help_value

    # When given an action, the formatter should simply return the value
    # of its 'help' attribute without any tinkering about it.
    help_string = formatter._get_help_string(_MyAction())
    eq_(help_string, help_value)

def test_parser():
    """ Tests whether the command line parser has expected attributes.
    """
    parser = main.get_parser()
    eq_(parser.prog, 'sec-wall')
    eq_(parser.description, main.description)
    eq_(parser.formatter_class, main.MyFormatter)
    eq_(len(parser._actions), 4)

    # A set of actions expected to be defined by the parser. Each name will
    # be popped off the 'expected_actions' set in a loop below. It is an error
    # if anything is left in the 'expected_actions' set when the loop finishes.
    base_expected_actions = set(['help', 'init', 'start', 'stop'])
    expected_actions = copy.deepcopy(base_expected_actions)

    expected = {
        'help': dict(option_strings=['-h', '--help'], help='show this help message and exit'),
        'init': dict(option_strings=[u'--init'], help=main.init_help),
        'start': dict(option_strings=[u'--start'], help=main.start_help),
        'stop': dict(option_strings=[u'--stop'], help=main.stop_help),
    }

    for action in parser._actions:
        assert_true(action.dest in base_expected_actions,
                    (action.dest, base_expected_actions))

        expected_option_strings = expected[action.dest]['option_strings']
        expected_help = expected[action.dest]['help']

        eq_(expected_option_strings, action.option_strings)
        eq_(expected_help, action.help)

        if action.dest == 'fork':
            expected_nargs = expected[action.dest]['nargs']
            expected_metavar = expected[action.dest]['metavar']

            eq_(expected_nargs, action.nargs)
            eq_(expected_metavar, action.metavar)

        expected_actions.remove(action.dest)

    eq_(len(expected_actions), 0, expected_actions)

def test_name_main():
    """ Tests the main module's behaviour when run directly.
    """
    if main.__file__.endswith('pyc'):
        main_file = main.__file__[:-1]
    else:
        main_file = main.__file__

    # A SystemExit is expected below because no command line arguments are given.
    try:
        d = {'__name__': '__main__'}
        execfile(main_file, d)
    except SystemExit:
        pass
    else:
        raise Exception('Expected a SystemExit here')

def test_main():
    """ Tests the behaviour of the main module's function which is invoked
    when the module's being rung directly, from the command line or using
    python -m switch.
    """
    base_args = {b'--fork':None, b'init':None, b'start':None, b'stop':None}

    for arg in base_args:
        for expected_is_https in ('1', '0'):

            args = copy.deepcopy(base_args)
            expected_config_dir = tempfile.mkdtemp()

            args[arg] = expected_config_dir

            with Replacer() as r:

                class _DummyParser(object):
                    def parse_args(*ignored_args, **ignored_kwargs):
                        return argparse.Namespace(**args)

                class _DummyCommand(object):
                    def __init__(self, config_dir, app_ctx, is_https):
                        eq_(config_dir, expected_config_dir)
                        assert_true(isinstance(app_ctx, ApplicationContext))

                        if arg == 'fork':
                            eq_(is_https, expected_is_https)

                    def run(self):
                        pass

                if arg == '--fork':
                    r.replace('sys.argv', ['--fork', expected_config_dir, expected_is_https])

                r.replace('secwall.main.get_parser', _DummyParser)
                r.replace('secwall.cli.Init', _DummyCommand)
                r.replace('secwall.cli.Start', _DummyCommand)
                r.replace('secwall.cli.Stop', _DummyCommand)
                r.replace('secwall.cli.Fork', _DummyCommand)

                main.run()
