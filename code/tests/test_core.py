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
import re
from uuid import uuid4

# nose
from nose.tools import assert_true, eq_

# sec-wall
from secwall.core import AuthResult, version_info, version, SecurityException, \
     SecWallException

def test_core():
    """ Tests info global to the module.
    """
    eq_(version_info, ('1', '0', '0'))
    eq_(version, '1.0.0')

def test_exceptions():
    """ Tests sec-wall specific exceptions.
    """
    assert_true(SecWallException, Exception)
    assert_true(SecurityException, SecWallException)

    description = uuid4().hex

    e = SecurityException(description)
    eq_(e.description, description)

def test_auth_result_nonzero():
    """ Tests AuthResult in boolean contexts.
    """
    # It's False by default.
    a1 = AuthResult()
    eq_(False, bool(a1))

    a2 = AuthResult(True)
    eq_(True, bool(a2))

def test_auth_result_properties():
    """ Tests that AuthResult's properties can be read correctly.
    """
    # Check the defaults first.
    a1 = AuthResult()
    eq_(False, a1.status)
    eq_('0', a1.code)
    eq_('', a1.description)

    status, code, description = [uuid4().hex for x in range(3)]

    a2 = AuthResult(status, code, description)
    eq_(status, a2.status)
    eq_(code, a2.code)
    eq_(description, a2.description)

def test_auth_result_repr():
    """ Tests the AuthResult's __repr__ output.
    """
    at_pattern = '\w*'
    status, code, description = [uuid4().hex for x in range(3)]
    a1 = AuthResult(status, code, description)
    r = repr(a1)

    pattern = '<AuthResult at {0} status={1} code={2} description={3}>'
    pattern = pattern.format(at_pattern, status, code, description)

    regexp = re.compile(pattern)

    assert_true(regexp.match(r) is not None, (pattern, r))
