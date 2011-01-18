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
import copy, time
from uuid import uuid4

# lxml
from lxml import etree

# nose
from nose.tools import assert_true, eq_

# sec-wall
from secwall.core import SecurityException
from secwall.wsse import soap_date_time_format, soapenv_namespace, \
     soap_body_path, soap_body_xpath, wsse_namespace, wsu_namespace, \
     wss_namespaces, wsse_password_type_text, wsse_password_type_digest, \
     supported_wsse_password_types, wsse_username_token_path, \
     wsse_username_token_xpath, wsse_username_path, wsse_username_xpath, \
     wsse_password_path, wsse_password_xpath, wsse_password_type_path, \
     wsse_password_type_xpath, wsse_nonce_path, wsse_nonce_xpath, \
     wsu_username_created_path, wsu_username_created_xpath, WSSE

raw_username = 'foo'
raw_password = 'bar'

base_config = {}
base_config['wsse-pwd-username'] = raw_username
base_config['wsse-pwd-password'] = raw_password
base_config['wsse-pwd-reject-expiry-limit'] = 1200
base_config['wsse-pwd-reject-empty-nonce-creation'] = True
base_config['wsse-pwd-reject-stale-tokens'] = True
base_config['wsse-pwd-password-digest'] = False
base_config['wsse-pwd-nonce-freshness-time'] = 1

def get_data(header=True, username=True, nonce=True, created=True,
             password_digest=False, valid_password=True, valid_username=True,
             send_password_type=True, supported_password_type=True):

    if header:

        wsse_username = '<wsse:Username>{0}</wsse:Username>'
        wsse_password = '<wsse:Password Type="{password_type}">{password_value}</wsse:Password>'
        wsu_created = '<wsu:Created>{0}</wsu:Created>'
        wsse_nonce = '<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{0}</wsse:Nonce>'

        if username:
            if valid_username:
                username = wsse_username.format(raw_username)
            else:
                username = wsse_username.format(uuid4().hex)
        else:
            username = ''

        if nonce:
            nonce_value = uuid4().hex.encode('base64')
            nonce = wsse_nonce.format(nonce_value)
        else:
            nonce = ''

        if created:
            created_value = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())
            created_value += '.000Z'
            created = wsu_created.format(created_value)
        else:
            created = ''
            created_value = ''

        if password_digest:
            if send_password_type:
                if supported_password_type:
                    password_type = wsse_password_type_digest
                else:
                    password_type = 'abcdef'
            else:
                password_type = ''

            wsse = WSSE()

            if valid_password:
                password_value = wsse._get_digest(raw_password, nonce_value, created_value)
            else:
                password_value = wsse._get_digest(uuid4().hex, nonce_value, created_value)

        else:
            if send_password_type:
                if supported_password_type:
                    password_type = wsse_password_type_text
                else:
                    password_type = 'abcdef'
            else:
                password_type = ''
            if valid_password:
                password_value = raw_password
            else:
                password_value = uuid4().hex

        password = wsse_password.format(password_type=password_type, password_value=password_value)

        return """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Header>
            <wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
              <wsse:UsernameToken wsu:Id="UsernameToken-1" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                {username}
                {password}
                {created}
                {nonce}
              </wsse:UsernameToken>
            </wsse:Security>
          </soapenv:Header>
          <soapenv:Body>
            <foo>
              <bar>123</bar>
            </foo>
          </soapenv:Body>
        </soapenv:Envelope>""".format(username=username, password=password,
                                      created=created, nonce=nonce)
    else:
        return """
          <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Body>
              <foo>
                <bar>123</bar>
              </foo>
            </soapenv:Body>
          </soapenv:Envelope>"""

def test_wsse_constants():
    eq_(soap_date_time_format, '%Y-%m-%dT%H:%M:%S.%fZ')
    eq_(soapenv_namespace, 'http://schemas.xmlsoap.org/soap/envelope/')
    eq_(soap_body_path, '/soapenv:Envelope/soapenv:Body')
    eq_(soap_body_xpath.path, '/soapenv:Envelope/soapenv:Body')
    eq_(wsse_namespace, 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd')
    eq_(wsu_namespace, 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd')
    eq_(wss_namespaces, {u'wsse': u'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
                         u'wsu': u'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
                         u'soapenv': u'http://schemas.xmlsoap.org/soap/envelope/'})
    eq_(wsse_password_type_text, 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText')
    eq_(wsse_password_type_digest, 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest')
    eq_(supported_wsse_password_types, (u'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText',
                                        u'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest'))
    eq_(wsse_username_token_path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken')
    eq_(wsse_username_token_xpath.path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken')
    eq_(wsse_username_path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken/wsse:Username')
    eq_(wsse_username_xpath.path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken/wsse:Username')
    eq_(wsse_password_path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken/wsse:Password')
    eq_(wsse_password_xpath.path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken/wsse:Password')
    eq_(wsse_password_type_path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken/wsse:Password/@Type')
    eq_(wsse_password_type_xpath.path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken/wsse:Password/@Type')
    eq_(wsse_nonce_path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken/wsse:Nonce')
    eq_(wsse_nonce_xpath.path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken/wsse:Nonce')
    eq_(wsu_username_created_path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken/wsu:Created')
    eq_(wsu_username_created_xpath.path, '/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken/wsu:Created')

def test_replace_username_token_elem_ok():
    """ Tests whether replacing the username token works fine.
    """
    wsse = WSSE()
    soap = etree.fromstring(get_data())

    wsse_password = wsse_password_xpath(soap)
    old_elem, attr = wsse._replace_username_token_elem(soap, wsse_password, 'Type')
    eq_(old_elem, raw_password)

def test_replace_username_token_elem_missing_type():
    """ Tests whether the expected exception is being raized while replacing
    the username token which doesn't have the 'Type' attribute.
    """
    wsse = WSSE()
    soap = etree.fromstring(get_data(True))

    # _replace_username_token_elem

    # Scenario 1) Everything goes well, SOAP's correct and contains the expected
    # element.
    wsse_password = wsse_password_xpath(soap)
    old_elem, attr = wsse._replace_username_token_elem(soap, wsse_password, 'Type')
    eq_(old_elem, raw_password)

    # Scenario 2) SOAP message doesn't have the expected element.
    soap_invalid = etree.fromstring(get_data(False))
    foobar = etree.XPath('//foo')(soap_invalid)
    try:
        wsse._replace_username_token_elem(soap_invalid, foobar, 'bar')
    except SecurityException, e:
        eq_(e.description, "Element [/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken] doesn't exist")
    else:
        raise Exception('A SecurityException was expected here')

def test_get_digest():
    """ Checks whether computing the digest works fine.
    """
    wsse = WSSE()

    # _get_digest
    nonce = 'NTA5OTA3YTk4Zjk5NGVhYWJhNTZkMTVkZGIzZjM2NzY=\n'
    digest = wsse._get_digest(raw_password, nonce, '2010-12-03T20:13:10.602Z')
    eq_(digest, 'OGhlMsnX6G7l859oktI6dUBfSjs=')

def test_error():
    """ Checks whether raising exceptions works fine.
    """
    wsse = WSSE()

    description = uuid4().hex
    elem = '/foo/bar/baz'

    try:
        wsse.error(description)
    except SecurityException, e:
        eq_(e.description, description)
    else:
        raise Exception('A SecurityException was expected here')

    try:
        wsse.error(description, elem)
    except SecurityException, e:
        eq_(e.description, '{0}. Element [{1}] doesn\'t exist'.format(description, elem))
    else:
        raise Exception('A SecurityException was expected here')

def test_nonce_default_unique():
    """ By default every nonce is considered to be unique and wsse.check_nonce
    should always return False, regardless of the input data.
    """
    wsse = WSSE()

    dummy1, dummy, dummy3 = range(3)
    eq_(wsse.check_nonce(dummy1, dummy, dummy3), False)

def test_nonce_not_unique():
    """ Subclasses of secwall.wsse.WSSE are free to override the 'check_nonce'.
    This particular subclass always returns True.
    """

    class _WSSE(WSSE):
        """ Simulates a subclass that actually validates used nonces.
        """
        def check_nonce(*ignored):
            return True

    wsse2 = _WSSE()
    data = get_data()
    config = copy.deepcopy(base_config)

    try:
        wsse2.validate(etree.fromstring(data), config)
    except SecurityException, e:
        eq_(len(e.description), 67)
        assert_true(e.description.startswith('Nonce ['))
        assert_true(e.description.endswith('] is not unique'))
    else:
        raise Exception('A SecurityException was expected here')

def test_invalid_input():
    """ Tests whether correct exceptions are being raised on invalid input.
    """
    wsse = WSSE()

    # a list of [method, how_many_param_sit_needs, description] elements
    test_data = [
        [wsse.on_invalid_username, 3, 'Invalid username or password'],
        [wsse.on_invalid_password, 4, 'Invalid username or password'],
        [wsse.on_username_token_expired, 3, 'UsernameToken has expired'],
        [wsse.on_nonce_non_unique, 4, 'Nonce [1] is not unique'],
    ]

    for meth, params_count, description in test_data:
        try:
            params = range(params_count)
            meth(*params)
        except SecurityException, e:
            eq_(e.description, description)
        else:
            msg = 'A SecurityException was expected here, meth={0}'.format(meth)
            raise Exception(msg)

def test_validate_invalid_input():
    """ Tests whether validating with invalid input data raises expected
    exceptions.
    """

    wsse = WSSE()
    soap = etree.fromstring(get_data())

    def _check_validate(data, expected):
        config = copy.deepcopy(base_config)
        soap = etree.fromstring(data)

        try:
            wsse.validate(soap, config)
        except SecurityException, e:
            eq_(e.description, expected)
        else:
            msg = 'A SecurityException was expected here, config=[{0}], expected=[{1}]'.format(config, expected)
            raise Exception(msg)

    test_data = [
            # Empty nonce creation time is given on input but config forbids it.
            [get_data(created=False), 'Both nonce and creation timestamp must be given'],

            # No username.
            [get_data(username=False), 'No username sent. Element [/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:UsernameToken/wsse:Username] doesn\'t exist'],

            # Invalid username.
            [get_data(valid_username=False), 'Invalid username or password'],

            # Invalid password.
            [get_data(valid_password=False), 'Invalid username or password'],

            # No password type sent.
            [get_data(send_password_type=False), 'No password type sent. Element [/soapenv:Envelope/' + \
                             'soapenv:Header/wsse:Security/' + \
                             'wsse:UsernameToken/wsse:Password/@Type]' + \
                             ' doesn\'t exist'],

            # Unsupported password type.
            [get_data(supported_password_type=False),
                 'Unsupported password type=[abcdef], not in ' + \
                 '[(u\'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\', ' + \
                 'u\'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\')]']
        ]

    for data, config in test_data:
        _check_validate(data, config)

def test_reject_expiry_limit():
    """ Tests whether expired messages are being rejected on validation.
    """
    soap = etree.fromstring(get_data())
    config = copy.deepcopy(base_config)
    config['wsse-pwd-reject-expiry-limit'] = 0.001

    # Make sure the message expires.
    time.sleep(1)

    wsse = WSSE()

    try:
        wsse.validate(soap, config)
    except SecurityException, e:
        eq_(e.description, 'UsernameToken has expired')
    else:
        raise Exception('A SecurityException was expected here')

def test_validate_password_digest_ok():
    """ Successfully validates a message whose password is of type PasswordDigest.
    """
    soap = etree.fromstring(get_data(password_digest=True))
    config = copy.deepcopy(base_config)
    config['wsse-pwd-password-digest'] = True

    wsse = WSSE()
    return_value = wsse.validate(soap, config)
    eq_(return_value, (True, 'foo'))
