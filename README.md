# Azure AD AWS Cli Authentication

Generates STS Tokens based on SAML Assertion from Azure AD (with MFA enabled also)


# System Requirements

* Python3.6+

# Installation

Simply run:

    $ pip install git+https://github.com/piontas/python-aada.git

In order to install with keyring for password management:

    $ pip install "git+https://github.com/piontas/python-aada.git#egg=python-aada [keyring]"

# Usage

To see help message:

    $ aada --help

To configure default profile

    $ aada configure

To configure named profile

    $ aada configure --profile <profile_name>

To login to Azure AD and assume role with SAML and pick role from a list

    $ aada login

To login to Azure AD and assume role with SAML with preselected role and account

    $ aada login -a <account number>  -r <rolename>

To login with named profile

    $ aada login --profile <profile_name>

To login in debug mode

    $ aada login -d

To login in non-headless mode

    $ aada login -n

## Configuration options
Before aada can be used, below details has to be collected:

* Azure Tenant ID
* Azure App ID URI
* Azure Username
* Azure MFA (Leave empty if not using MFA).
* AWS CLI session duration (3600 seconds by default)

MFA Options:
* *PhoneAppOTP* - mobile phone application generated token
* *OneWaySMS* - sms based token
* *PhoneAppNotification* - mobile phone application notification
* *TwoWayVoiceMobile* - voice call confirmation

# Running in Docker

## Build

First build the container. It will install Chrome and configure `pyppeteer` to
use the downloaded version instead of downloading each time you run the
container.

```
docker build -t localhost/python-aada:latest -f Dockerfile .
```

You can run the container now but must specify the `seccomp` profile to allow
Chrome to run it's sandbox. This mounts your local `$HOME/.aws` directory for
access to profiles.

```
docker run -it --rm \
    -v $HOME/.aws:/home/chrome/.aws \
    --log-driver none \
    --security-opt seccomp:chrome.json \
    localhost/aada login --profile <profile-name>
```

# TODO

* Documentation
* Tests
* Installation steps
* Logging, debugging
