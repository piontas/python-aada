import sys
import logging
import argparse

from botocore.session import Session, get_session
from . import __version__
from .login import Login
from .configure import Configure

LOG = logging.getLogger('aada')
LOG_FORMAT = (
    '%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s')


class Cli(object):
    COMMAND_CHOICES = ('login', 'configure')

    def __init__(self, args=None):
        if args is None:
            self.args = sys.argv[1:]
        else:
            self.args = args
        self._session = None
        self._parsed_args = None

    def _create_parser(self):
        parser = argparse.ArgumentParser(
            prog='aada',
            description='Azure AD AWS CLI Authentication',
            usage='aada <command> [<args>].\n\nAllowed commands are:\n'
                  'login       Login to Azure AD and assume AWS Role\n'
                  'configure   Configure Azure AD and profile')
        parser.add_argument("-v", "--version", action="version",
                            version="{}".format(__version__))
        parser.add_argument('-p', '--profile', help='AWS Profile')
        parser.add_argument('command', choices=self.COMMAND_CHOICES)
        return parser

    def _login(self):
        login = Login(self._session)
        return login()

    def _configure(self):
        configure = Configure(self._session)
        return configure(self._parsed_args)

    def main(self):
        parser = self._create_parser()
        self._parsed_args = parser.parse_args(self.args)

        if self._parsed_args.profile:
            self._session = Session(profile=self._parsed_args.profile)
        else:
            self._session = get_session()

        return self.__getattribute__('_{}'.format(self._parsed_args.command))()


def main():
    cli = Cli()
    return cli.main()


if __name__ == "__main__":
    sys.exit(main())
