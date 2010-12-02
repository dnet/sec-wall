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

# nose
from nose.tools import assert_true, eq_

# sec-wall
from secwall.wsse import soap_date_time_format, soapenv_namespace, \
     soap_body_path, soap_body_xpath, wsse_namespace, wsu_namespace, \
     wss_namespaces, wsse_password_type_text, wsse_password_type_digest, \
     supported_wsse_password_types, wsse_username_token_path, \
     wsse_username_token_xpath, wsse_username_path, wsse_username_xpath, \
     wsse_password_path, wsse_password_xpath, wsse_password_type_path, \
     wsse_password_type_xpath, wsse_nonce_path, wsse_nonce_xpath, \
     wsu_username_created_path, wsu_username_created_xpath, wsu_expires_path, \
     wsu_expires_xpath, WSSE

def test_wsse():
    pass
