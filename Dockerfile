# Dionaea Dockerfile by MO 
#
# VERSION 0.5
FROM ubuntu:14.04.1
MAINTAINER MO

# Setup apt
RUN apt-get update -y
RUN apt-get dist-upgrade -y
ENV DEBIAN_FRONTEND noninteractive

# Install packages 
RUN apt-get install -y supervisor python-lxml python-mysqldb python-requests git
RUN cd /opt && git clone https://github.com/rep/hpfeeds.git && cd hpfeeds && python setup.py install

# Setup user, groups and configs
RUN addgroup --gid 2000 tpot
RUN adduser --system --no-create-home --shell /bin/bash --uid 2000 --disabled-password --disabled-login --gid 2000 tpot
RUN mkdir -p /data/ews/spool/  /data/ews/log/ /data/ews/json/ /opt/ews/
ADD supervisord.conf /etc/supervisor/conf.d/supervisord.conf
ADD crontab /etc/
ADD ews.py /opt/ews/
ADD moduls/* /opt/ews/moduls/
ADD GPL /opt/ews/
ADD ews.cfg.default /opt/ews/dist/

# Clean up 
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Start dionaea
CMD ["/usr/bin/supervisord"]
