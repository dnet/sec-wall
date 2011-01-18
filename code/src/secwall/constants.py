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

__all__ = ['AUTH_XPATH_NO_DATA', 'AUTH_XPATH_EXPR_MISMATCH', 'AUTH_CERT_NO_SUBJECT',
           'AUTH_CERT_NO_VALUE', 'AUTH_CERT_VALUE_MISMATCH', 'AUTH_WSSE_NO_DATA',
           'AUTH_WSSE_VALIDATION_ERROR', 'AUTH_BASIC_NO_AUTH', 'AUTH_BASIC_INVALID_PREFIX',
           'AUTH_BASIC_USERNAME_OR_PASSWORD_MISMATCH',  'AUTH_DIGEST_NO_AUTH',
           'AUTH_DIGEST_USERNAME_MISMATCH',  'AUTH_DIGEST_REALM_MISMATCH',
           'AUTH_DIGEST_URI_MISMATCH', 'AUTH_DIGEST_RESPONSE_MISMATCH',
           'AUTH_DIGEST_NO_HEADER', 'AUTH_DIGEST_HEADER_MISMATCH',
           'AUTH_CUSTOM_HTTP_NO_HEADER', 'AUTH_CUSTOM_HTTP_HEADER_MISMATCH']

AUTH_XPATH_NO_DATA = '0001.0001'
AUTH_XPATH_EXPR_MISMATCH = '0001.0002'

AUTH_CERT_NO_SUBJECT = '0002.0001'
AUTH_CERT_NO_VALUE = '0002.0002'
AUTH_CERT_VALUE_MISMATCH = '0002.0003'

AUTH_WSSE_NO_DATA = '0003.0001'
AUTH_WSSE_VALIDATION_ERROR = '0003.0002'

AUTH_BASIC_NO_AUTH = '0004.0001'
AUTH_BASIC_INVALID_PREFIX = '0004.0002'
AUTH_BASIC_USERNAME_OR_PASSWORD_MISMATCH = '0004.0003'

AUTH_DIGEST_NO_AUTH = '0005.0001'
AUTH_DIGEST_USERNAME_MISMATCH = '0005.0002'
AUTH_DIGEST_REALM_MISMATCH = '0005.0003'
AUTH_DIGEST_URI_MISMATCH = '0005.0004'
AUTH_DIGEST_RESPONSE_MISMATCH = '0005.0005'
AUTH_DIGEST_NO_HEADER = '0005.0006'
AUTH_DIGEST_HEADER_MISMATCH = '0005.0007'

AUTH_CUSTOM_HTTP_NO_HEADER = '0006.0001'
AUTH_CUSTOM_HTTP_HEADER_MISMATCH = '0006.0002'
