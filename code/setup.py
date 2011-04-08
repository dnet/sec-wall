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

      scripts = ["scripts/sec-wall"],

      author = "Dariusz Suchojad",
      author_email = "dsuch at gefira.pl",
      url = "http://sec-wall.gefira.pl/",
      description = "A feature packed high-performance security proxy",
      long_description = "sec-wall is a high-performance security proxy supporting SSL/TLS, WS-Security, HTTP Auth Basic/Digest, extensible authentication schemes based on custom HTTP headers and XPath expressions, powerful URL matching/rewriting and an optional headers enrichment. It's a security wall you can conveniently fence the otherwise defenseless backend servers with.",
      platforms = ["OS Independent"],
      license = "GNU General Public License (GPL) 3",

      package_dir = {"":b"src"},
      packages = find_packages(b"src"),

      namespace_packages = [b"secwall"],

      zip_safe = False,

      classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Other Audience',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'License :: OSI Approved :: Python Software Foundation License',
        'Intended Audience :: Developers',
        'Topic :: Communications',
        'Topic :: Internet',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Firewalls'
        ],
)
