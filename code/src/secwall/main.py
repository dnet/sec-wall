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
from secwall import app_context, cli, version

if __name__ == '__main__':

    description = 'sec-wall {0}- A feature packed high-performance security proxy'.format(version)

    parser = argparse.ArgumentParser(prog='sec-wall.sh', description=description)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--init', help='Initializes a config directory')
    group.add_argument('--start', help='Starts sec-wall in a given directory')
    group.add_argument('--stop', help='Stops a sec-wall instance running in a given directory')

    args = parser.parse_args()

    # Using a mutually exclusive group above gurantees that we'll have exactly
    # one option to pick here.
    command, config_dir = [(k, v) for k, v in args._get_kwargs() if v][0]
    config_dir = os.path.abspath(config_dir)

    app_ctx = ApplicationContext(app_context.SecWallContext())

    handler = getattr(cli, command.capitalize())()
    handler.run(config_dir, app_ctx)
