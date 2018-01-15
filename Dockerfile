FROM python:3.6-jessie

ADD . /var/python-aada

RUN apt-get install -y libssl-dev libfreetype6 libfreetype6-dev libfontconfig1 libfontconfig1-dev \
    && cd /var/python-aada && python /var/python-aada/setup.py install

CMD ["aada"]