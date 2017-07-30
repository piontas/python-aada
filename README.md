# Azure AD AWS Cli Authentication

Generates STS Tokens based on SAML Assertion from Azure AD (with MFA enabled also)


# System Requirements

* Python2.7 or Python3.3+
* Selenium webdriver like [PhantomJS](http://phantomjs.org) or [Chrome driver](https://sites.google.com/a/chromium.org/chromedriver/)

## How to install PhantomJS on Linux Debian

Install prerequisites

    $ sudo apt-get install -y libssl-dev libfreetype6 libfreetype6-dev libfontconfig1 libfontconfig1-dev
    
Download and unpack

    $ wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2
    $ tar xvjf phantomjs-2.1.1-linux-x86_64.tar.bz2 
    $ mv phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin/


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

To login to Azure AD and assume role with SAML

    $ aada login
    
To login with named profile

    $ aada login --profile <profile_name>
    

# TODO

* Documentation
* Tests
* Installation steps
* Logging, debugging
