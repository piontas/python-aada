FROM python:3.6-jessie

ENV PHANTOMJS phantomjs-2.1.1-linux-x86_64

ADD . /var/python-aada

RUN apt-get install -y libssl-dev libfreetype6 libfreetype6-dev libfontconfig1 libfontconfig1-dev \
    && wget -O phantomjs.tar.bz2 "https://bitbucket.org/ariya/phantomjs/downloads/${PHANTOMJS}.tar.bz2" \
    && tar xvjf phantomjs.tar.bz2 && mv "${PHANTOMJS}/bin/phantomjs" /usr/local/bin/ \
    && cd /var/python-aada && python /var/python-aada/setup.py install

CMD ["aada"]