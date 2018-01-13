from __future__ import absolute_import
import os
import base64
import uuid
import zlib
import getpass
import json
import requests
import time

from datetime import datetime
from xml.etree import ElementTree as ET

import boto3
from awscli.customizations.configure.writer import ConfigFileWriter

import asyncio
from pyppeteer.launcher import launch

from .compat import quote, raw_input
from . import LOGIN_URL, MFA_WAIT_METHODS


class MfaException(Exception):
    pass


class Login:
    _SAML_REQUEST = \
        '<samlp:AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xml' \
        'ns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id_{id}" Version' \
        '="2.0" IsPassive="false" IssueInstant="{date}" AssertionConsumerServ' \
        'iceURL="https://signin.aws.amazon.com/saml"><Issuer xmlns="urn:oasis' \
        ':names:tc:SAML:2.0:assertion">{app_id}</Issuer><samlp:NameIDPolicy F' \
        'ormat="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></sa' \
        'mlp:AuthnRequest>'

    _BEGIN_AUTH_URL = '{url}/common/SAS/BeginAuth'
    _END_AUTH_URL = '{url}/common/SAS/EndAuth'
    _PROCESS_AUTH_URL = '{url}/common/SAS/ProcessAuth'
    _KMSI_URL = '{url}/kmsi'
    _SAML_URL = '{url}/{tenant_id}/saml2?SAMLRequest={saml_request}'
    _REFERER = '{url}/{tenant_id}/login'

    _CREDENTIALS = ['aws_access_key_id', 'aws_secret_access_key',
                    'aws_session_token']

    _MFA_DELAY = 3

    def __init__(self, session, saml_request=None):
        self._session = session
        self._config = self._session.get_scoped_config()
        config_writer = ConfigFileWriter()
        self._config_writer = config_writer
        self._azure_tenant_id = self._config.get('azure_tenant_id')
        self._azure_app_id_uri = self._config.get('azure_app_id_uri')
        self._azure_mfa = self._config.get('azure_mfa')
        self._azure_username = self._config.get('azure_username')
        self.mfa_token = None
        self.browser = launch()

        if saml_request:
            self._SAML_REQUEST = saml_request

    def __call__(self):
        return self._login()

    def _set_config_value(self, key, value):
        section = 'default'

        if self._session.profile is not None:
            section = 'profile {}'.format(self._session.profile)

        config_filename = os.path.expanduser(
            self._session.get_config_variable('config_file'))
        updated_config = {'__section__': section, key: value}

        if key in self._CREDENTIALS:
            config_filename = os.path.expanduser(
                self._session.get_config_variable('credentials_file'))
            section_name = updated_config['__section__']

            if section_name.startswith('profile '):
                updated_config['__section__'] = section_name[8:]
        self._config_writer.update_config(updated_config, config_filename)

    def _build_saml_login_url(self):
        saml_request = base64.b64encode(zlib.compress(
            self._SAML_REQUEST.strip().format(
                date=datetime.now().strftime("%Y-%m-%dT%H:%m:%SZ"),
                tenant_id=self._azure_tenant_id, id=uuid.uuid4(),
                app_id=self._azure_app_id_uri).encode('ascii'))[2:-4]).decode()
        return self._SAML_URL.format(
            url=LOGIN_URL, tenant_id=self._azure_tenant_id,
            saml_request=quote(saml_request))

    async def _render_js_form(self, url, username, password, mfa=None):
        page = await self.browser.newPage()
        await page.goto(url)
        await page.waitForSelector('input[name="loginfmt"]:not(.moveOffScreen)')
        await page.focus('input[name="loginfmt"]')
        for l in username:
            await page.keyboard.sendCharacter(l)
        await page.click('input[type=submit]')
        await page.waitForSelector('input[name="passwd"]:not(.moveOffScreen)')
        await page.focus('input[name="passwd"]')
        for l in password:
            await page.keyboard.sendCharacter(l)
        await page.click('input[type=submit]')

        if mfa:
            await page.waitForSelector('input[name="GeneralVerify"]')
            flow_token = await page.evaluate('() => $Config.sFT')
            ctx = await page.evaluate('() => $Config.sCtx')
            data = {
                'login': username,
                'AuthMethodId': mfa,
                'Method': 'BeginAuth',
                'ctx': ctx,
                'flowToken': flow_token
            }
            await page.setContent(self._mfa_authentication(data))

        await page.waitForSelector('form[action="/kmsi"]')
        await page.click('input[type=submit]')
        await page.waitForSelector('input[name="SAMLResponse"]')
        element = await page.querySelector('input[name="SAMLResponse"]')
        saml_response = await element.evaluate('(element) => element.value')

        return {'SAMLResponse': saml_response}

    @staticmethod
    def _get_aws_roles(saml_response):
        aws_roles = []
        for attribute in ET.fromstring(base64.b64decode(saml_response)).iter(
                '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if (attribute.get('Name') ==
                    'https://aws.amazon.com/SAML/Attributes/Role'):
                for value in attribute.iter(
                        '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                    aws_roles.append(value.text)

        for role in aws_roles:
            chunks = role.split(',')
            if 'saml-provider' in chunks[0]:
                new_role = chunks[1] + ',' + chunks[0]
                index = aws_roles.index(role)
                aws_roles.insert(index, new_role)
                aws_roles.remove(role)
        return aws_roles

    @staticmethod
    def _assume_role(role_arn, principal_arn, saml_response):
        return boto3.client('sts').assume_role_with_saml(
            RoleArn=role_arn, PrincipalArn=principal_arn,
            SAMLAssertion=saml_response) #,DurationSeconds=28800

    def _save_creadentials(self, credentials, role_arn):
        self._set_config_value('aws_role_arn', role_arn)
        self._set_config_value('aws_access_key_id', credentials['AccessKeyId'])
        self._set_config_value('aws_secret_access_key', credentials[
            'SecretAccessKey'])
        self._set_config_value('aws_session_token', credentials['SessionToken'])

    @staticmethod
    def _choose_role(aws_roles):
        count_roles = len(aws_roles)
        if count_roles > 1:
            allowed_values = list(range(1, count_roles + 1))
            for i, role in enumerate(aws_roles, start=1):
                print('[ {} ]: {}'.format(i, role.split(',')[0]))

            print('Choose the role you would like to assume:')
            selected_role = int(raw_input('Selection: '))
            while selected_role not in allowed_values:
                print('Invalid role index, please try again')
                selected_role = int(raw_input('Selection: '))
            return aws_roles[selected_role - 1].split(',')[0], aws_roles[
                selected_role - 1].split(',')[1]
        return aws_roles[0].split(',')[0], aws_roles[0].split(',')[1]

    @staticmethod
    def _post(session, url, data, headers):
        return json.loads(session.post(url, data=data, headers=headers).text)

    def _mfa_authentication(self, data):
        """
        :param data:
        :return:
        """
        login = data.pop('login')
        session = requests.Session()
        referer = self._REFERER.format(url=LOGIN_URL,
                                       tenant_id=self._azure_tenant_id)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json', 'Referer': referer}

        json_response = self._post(session, self._BEGIN_AUTH_URL.format(
            url=LOGIN_URL), json.dumps(data), headers)

        if not json_response['Success']:
            raise MfaException

        data = {
            'Method': 'EndAuth',
            'FlowToken': json_response['FlowToken'],
            'SessionId': json_response['SessionId'],
            'Ctx': json_response['Ctx'],
            'AuthMethodId': self._azure_mfa
        }

        if self._azure_mfa not in MFA_WAIT_METHODS:
            self.mfa_token = raw_input('Azure MFA Token: ')
            data['AdditionalAuthData'] = self.mfa_token

        json_response = self._post(session, self._END_AUTH_URL.format(
            url=LOGIN_URL), json.dumps(data), headers)

        print('Processing MFA authentication...')
        while json_response['ResultValue'] == 'AuthenticationPending':
            time.sleep(self._MFA_DELAY)
            json_response = self._post(session, self._END_AUTH_URL.format(
                url=LOGIN_URL), json.dumps(data), headers)

        data = {
            "login": login,
            "flowToken": json_response['FlowToken'],
            "request": json_response['Ctx'],
            "mfaAuthMethod": self._azure_mfa,
            "GeneralVerify": ''
        }

        headers = {'Content-type': 'application/x-www-form-urlencoded',
                   'Referer': referer}
        response = session.post(self._PROCESS_AUTH_URL.format(url=LOGIN_URL),
                                data, headers=headers)
        return response.text

    def _login(self):
        """

        :param parsed_args:
        :return:
        """
        url = self._build_saml_login_url()
        print(url)

        username_input = self._azure_username
        print('Azure username: {}'.format(self._azure_username))
        password_input = getpass.getpass('Azure password: ')

        data = asyncio.get_event_loop().run_until_complete(
            self._render_js_form(url, username_input, password_input,
                                 self._azure_mfa))

        saml_response = data['SAMLResponse']
        role, principal = self._choose_role(self._get_aws_roles(saml_response))

        print('Assuming AWS Role: {}'.format(role))
        sts_token = self._assume_role(role, principal, saml_response)
        credentials = sts_token['Credentials']
        self._save_creadentials(credentials, role)

        print('\n-------------------------------------------------------------')
        print('Your access key pair has been stored in the AWS configuration\n'
              'file under the {} profile.'.format(self._session.profile))
        print('Credentials expires at {:%Y-%m-%d %H:%M:%S}.'.format(
            credentials['Expiration']))
        print('-------------------------------------------------------------\n')
        return 0
