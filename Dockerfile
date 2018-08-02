FROM centos:7

LABEL maintainer Anthony Scata <anthony.scata@auspost.com.au>

ENV PYTHON_BIN_PATH='/opt/rh/rh-python36/root/usr/bin/'
ENV CHROME_EXECUTABLE_PATH='/opt/google/chrome/chrome'

# the tool uses chrome to login via a headless browser, it has dependnecies so easiest to install them
# with a single command as the dependency list is long
RUN curl --silent --location https://intoli.com/install-google-chrome.sh | sh -

RUN /usr/bin/yum -y install centos-release-scl
RUN /usr/bin/yum -y install rh-python36

RUN /usr/bin/yum -y install git
RUN "${PYTHON_BIN_PATH}/pip3" install --upgrade pip git+https://github.com/Lee-SL/python-aada.git

ENTRYPOINT ["/usr/bin/scl"]
CMD ["enable", "rh-python36", "--", "aada", "configure", "--profile"]