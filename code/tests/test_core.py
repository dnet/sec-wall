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
from datetime import datetime, timedelta
from logging import makeLogRecord
from uuid import uuid4

# nose
from nose.tools import assert_true, eq_

# sec-wall
from secwall.core import AuthResult, InvocationContext, LoggingFormatter, \
     SecurityException, SecWallException, version_info, version

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
    eq_('-1', a1.code)
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
    auth_info = {b'abc':b'def'}
    a1 = AuthResult(status, code, description)
    a1.auth_info = auth_info
    r = repr(a1)

    pattern = '<AuthResult at {0} status={1} code={2} description={3} auth_info={{abc: def}}\n>'
    pattern = pattern.format(at_pattern, status, code, description)

    regexp = re.compile(pattern)

    assert_true(regexp.match(r) is not None, (pattern, r))

def test_logging_formatter():
    """ Makes sure that the logging formatter prepends messages
    with the expected string.
    """
    lf = LoggingFormatter()
    _msg = uuid4().hex
    d = {'msg': _msg}
    record = makeLogRecord(d)
    msg = lf.format(record)

    eq_(msg, 'sec-wall {0}'.format(_msg))

def test_invocation_context_init_parameters():
    """ Makes sure the parameters passed into InocationContext.__init___
    are being assigned to the instance correctly.
    """
    (_instance_name,  _instance_unique,  _message_number, _proc_start,
     _proc_end,  _ext_start,  _ext_end,  _env,  _url_config, _client_cert,
     _data,  _remote_address,  _auth_result,  _config_type,  _path_info,
     _query_string,  _client_address,  _request_method) = [uuid4().hex for x in range(18)]

    ctx = InvocationContext(_instance_name,  _instance_unique,
            _message_number, _proc_start, _proc_end,  _ext_start,  _ext_end,
            _env,  _url_config, _client_cert, _data,  _remote_address,
            _auth_result,  _config_type,  _path_info, _query_string,
            _client_address,  _request_method)

    eq_(ctx.instance_name, _instance_name)
    eq_(ctx.instance_unique, _instance_unique)
    eq_(ctx.message_number, _message_number)
    eq_(ctx.proc_start, _proc_start)
    eq_(ctx.proc_end, _proc_end)
    eq_(ctx.ext_start, _ext_start)
    eq_(ctx.ext_end, _ext_end)
    eq_(ctx.env, _env)
    eq_(ctx.url_config, _url_config)
    eq_(ctx.client_cert, _client_cert)
    eq_(ctx.data, _data)
    eq_(ctx.remote_address, _remote_address)
    eq_(ctx.auth_result, _auth_result)
    eq_(ctx.config_type, _config_type)
    eq_(ctx.path_info, _path_info)
    eq_(ctx.query_string, _query_string)
    eq_(ctx.client_address, _client_address)
    eq_(ctx.request_method, _request_method)
    eq_(ctx.stop_watch_format, '{0.seconds}.{0.microseconds:06d}')
    eq_(ctx.invocation_id, '{0}/{1}/{2}'.format(_instance_name, _instance_unique,
                                                _message_number))

def test_invocation_context_format_log_message():
    """ Tests the correctness of formatting of logging messages.
    """
    _auth1 = AuthResult(True)
    _auth2 = AuthResult(False, uuid4().hex)

    for _auth_result in _auth1, _auth2:
        for _needs_details in True, False:

            _now = datetime.now()
            _start_to_ext_start = timedelta(seconds=1, microseconds=129)
            _ext_took = timedelta(seconds=3, microseconds=9017)
            _ext_end_to_proc_end = timedelta(seconds=7, microseconds=3511)

            _proc_start = _now
            _proc_end = _now + _start_to_ext_start + _ext_took + _ext_end_to_proc_end
            _ext_start = _now + _start_to_ext_start
            _ext_end = _now + _start_to_ext_start + _ext_took

            _env = {'HTTP_USER_AGENT':uuid4().hex, 'SERVER_SOFTWARE':uuid4().hex,
                    'SERVER_NAME':uuid4().hex, 'SERVER_PORT':uuid4().hex}

            _code = uuid4().hex

            (_instance_name,  _instance_unique,  _message_number, _url_config, _client_cert,
             _data,  _remote_address, _config_type,  _path_info,
             _query_string,  _client_address,  _request_method) = [uuid4().hex for x in range(12)]

            ctx = InvocationContext(_instance_name,  _instance_unique,
                    _message_number, _proc_start, _proc_end,  _ext_start,  _ext_end,
                    _env,  _url_config, _client_cert, _data,  _remote_address,
                    _auth_result,  _config_type,  _path_info, _query_string,
                    _client_address,  _request_method)

            msg = ctx.format_log_message(_code, _needs_details)

            if _needs_details:

                (invocation_id, code, proc_start, remote_address, req_info,
                 secwall_overhead, ext_overhead, proc_total, auth_result,
                 auth_code, http_user_agent, server_software, server_name, server_port,
                 config_type, data) = msg.split(';')
            else:
                (invocation_id, code, proc_start, remote_address, req_info,
                 secwall_overhead, ext_overhead, proc_total, auth_result,
                 auth_code) = msg.split(';')

            eq_(invocation_id, ctx.invocation_id)
            eq_(code, _code)
            eq_(proc_start, str(_proc_start))
            eq_(remote_address, _remote_address)
            eq_(req_info, _request_method + ' ' + _path_info + _query_string)

            _proc_total = _proc_end - _proc_start
            _ext_overhead = _ext_end - _ext_start
            _secwall_overhead = _proc_total - _ext_overhead

            eq_(proc_total, str(_proc_total.seconds) + '.' + str(_proc_total.microseconds).zfill(6))
            eq_(ext_overhead, str(_ext_overhead.seconds) + '.' + str(_ext_overhead.microseconds).zfill(6))
            eq_(secwall_overhead, str(_secwall_overhead.seconds) + '.' + str(_secwall_overhead.microseconds).zfill(6))

            if _auth_result:
                eq_(auth_result, '0')
            else:
                eq_(auth_result, '1')

            eq_(auth_code, _auth_result.code)

            if _needs_details:
                eq_(http_user_agent, '"{0}"'.format(_env.get('HTTP_USER_AGENT')))
                eq_(server_software, _env.get('SERVER_SOFTWARE'))
                eq_(server_name, _env.get('SERVER_NAME'))
                eq_(server_port, _env.get('SERVER_PORT'))
                eq_(config_type, _config_type)
                eq_(data, _data)
