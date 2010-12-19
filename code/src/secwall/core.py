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

version_info = ('1', '0', '0')
version = '.'.join(version_info)

class SecWallException(Exception):
    """ A base class for any exception raised by sec-wall
    """

class SecurityException(SecWallException):
    """ Indicates problems with validating incoming requests. The 'description'
    attribute holds textual information suitable for showing to human users.
    """
    def __init__(self, description):
        self.description = description

class AuthResult(object):
    """ Represents the result of validating a URL against the config. 'status'
    is the main boolean flag indicating whether the successful was successful
    or not. 'code' equal to '0' means success and any other value
    is a failure, note that 'code' may be a multi-character string including
    punctuation. 'description' is an optional attribute holding any additional
    textual information a callee might wish to pass to the calling layer.

    Instances of this class are considered True or False in boolean comparisons
    according to the boolean value of self.status.
    """
    def __init__(self, status=False, code='0', description=''):
        self.status = status
        self.code = code
        self.description = description

    def __repr__(self):
        return '<{0} at {1} status={2} code={3} description={4}>'.format(
            self.__class__.__name__, hex(id(self)), self.status, self.code,
            self.description)

    def __nonzero__(self):
        """ Returns the boolean value of self.status. Useful when an instance
        must be compared in a boolean context.
        """
        return bool(self.status)
