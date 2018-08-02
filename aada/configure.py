import os

from awscli.customizations.configure.writer import ConfigFileWriter
from botocore.exceptions import ProfileNotFound

from . import MFA_ALLOWED_METHODS


class Configure:
    PROMPT_VALUES = [
        ('azure_tenant_id', 'Azure tenant id'),
        ('azure_app_id_uri', 'Azure app id uri'),
        ('azure_username', 'Azure username'),
        ('azure_mfa', 'If Azure MFA enabled: {:}'.format(', '.join(
            MFA_ALLOWED_METHODS))),
        ('session_duration_hours', 'AWS CLI session duration in hours'),
        # ('azure_kmsi', 'Azure Keep me signed In'),
        ('aws_role_arn', 'AWS default role arn')
    ]

    def __init__(self, session=None):
        self._session = session
        config_writer = ConfigFileWriter()
        self._config_writer = config_writer

    def __call__(self, parsed_args):
        return self._configure(parsed_args)

    @staticmethod
    def _get_value(value, prompt_text=''):
        response = input('{} [{}]: '.format(prompt_text, value))
        if not response:
            response = None
        return response

    def _configure(self, parsed_args):
        new_values = {}
        try:
            config = self._session.get_scoped_config()
        except ProfileNotFound:
            config = {}
        for config_name, prompt_text in self.PROMPT_VALUES:
            current_value = config.get(config_name)
            new_value = self._get_value(current_value, prompt_text)
            if new_value is not None and new_value != current_value:
                new_values[config_name] = new_value
        config_filename = os.path.expanduser(
            self._session.get_config_variable('config_file'))
        if new_values:
            self._write_credentials(new_values, parsed_args.profile)
            if parsed_args.profile is not None:
                new_values['__section__'] = ('profile {}'.format(
                    parsed_args.profile))
            self._config_writer.update_config(new_values, config_filename)
        return 0

    def _write_credentials(self, new_values, profile):
        credential_values = {}
        if 'aws_access_key_id' in new_values:
            credential_values['aws_access_key_id'] = new_values.pop(
                'aws_access_key_id')
        if 'aws_secret_access_key' in new_values:
            credential_values['aws_secret_access_key'] = new_values.pop(
                'aws_secret_access_key')
        if credential_values:
            if profile is not None:
                credential_values['__section__'] = profile
            credentials_filename = os.path.expanduser(
                self._session.get_config_variable('credentials_file'))
            self._config_writer.update_config(credential_values,
                                              credentials_filename)
