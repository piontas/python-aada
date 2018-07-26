# Azure AD AWS Cli Authentication

Generates STS Tokens based on SAML Assertion from Azure AD (with MFA enabled also)


# System Requirements

* Python3.6+

# Installation

Simply run:

    $ pip install git+https://github.com/piontas/python-aada.git


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
    

# TODO

* Documentation
* Tests
* Installation steps
* Logging, debugging
