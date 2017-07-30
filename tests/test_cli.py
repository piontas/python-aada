from subprocess import call
from sys import executable

import pytest


@pytest.fixture(params=("--help", "login", "configure"))
def command(request):
    """ Return the command to run.

    """
    return request.param


def test_script(command):
    """ Test command line execution.

    """
    # Call with the --help option as a basic sanity check.
    cmdl = "{:s} -m aada.cli {:s} --help".format(executable, command)
    assert 0 == call(cmdl.split())
    return


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
