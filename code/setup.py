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

from setuptools import setup, find_packages

version = "1.0.0"

setup(
      name = "sec-wall",
      version = version,

      author = "Dariusz Suchojad",
      author_email = "dsuch at gefira.pl",
      url = "https://launchpad.net/sec-wall",

      package_dir = {"":"src"},
      packages = find_packages("src"),

      namespace_packages = ["secwall"],

      zip_safe = False,
)