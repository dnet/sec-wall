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
import argparse, os

# Spring Python
from springpython.context import ApplicationContext

# sec-wall
from secwall import app_context, cli
from secwall.core import version

description = 'sec-wall {0}- A feature packed high-performance security proxy'.format(version)

init_help = 'Initializes a config directory'
start_help = 'Starts sec-wall in the given directory'
stop_help = 'Stops a sec-wall instance running in the given directory'
fork_help = 'Starts one of the sec-wall\'s subprocesses'

class MyFormatter(argparse.ArgumentDefaultsHelpFormatter):
    """ A nicer help formatter, setting 'max_help_position' to that value
    ensures the help doesn't span multiple lines in an awkward way.
    """
    max_help_position = 35

    def __init__(self, **kwargs):
        super(MyFormatter, self).__init__(max_help_position=self.max_help_position,
                                          **kwargs)

    def _get_help_string(self, action):
        """ Overridden from the super-class to prevent showing of defaults,
        as there are no default values.
        """
        return action.help

def get_parser():
    """ Returns an argparse.ArgumentParser instance for parsing the command line
    arguments.
    """
    parser = argparse.ArgumentParser(prog='sec-wall', description=description,
                                     formatter_class=MyFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--init', help=init_help)
    group.add_argument('--start', help=start_help)
    group.add_argument('--stop', help=stop_help)
    group.add_argument('--fork', help=fork_help, nargs=2, metavar=('config_dir', 'is_https'))

    return parser

def run():
    parser = get_parser()
    args = parser.parse_args()

    # Using a mutually exclusive group in 'get_parser' gurantees that we'll have
    # exactly one option to pick here.
    command, config_info = [(k, v) for k, v in args._get_kwargs() if v][0]
    if command == 'fork':
        config_dir, is_https = config_info
    else:
        config_dir = config_info
        is_https = None

    config_dir = os.path.abspath(config_dir)

    app_ctx = ApplicationContext(app_context.SecWallContext())

    handler_class = getattr(cli, command.capitalize())
    handler_class(config_dir, app_ctx, is_https).run()

if __name__ == '__main__':
    run()
