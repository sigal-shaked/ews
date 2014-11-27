# Dionaea Dockerfile by MO 
#
# VERSION 0.3
FROM ubuntu:14.04.1
MAINTAINER MO

# Setup apt
RUN apt-get update -y
RUN apt-get dist-upgrade -y
ENV DEBIAN_FRONTEND noninteractive

# Install packages 
RUN apt-get install -y supervisor

# Setup user, groups and configs
RUN addgroup --gid 2000 tpot
RUN adduser --system --no-create-home --shell /bin/bash --uid 2000 --disabled-password --disabled-login --gid 2000 tpot
ADD supervisord.conf /etc/supervisor/conf.d/supervisord.conf
ADD crontab /etc/crontab

# Clean up 
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Start dionaea
CMD ["/usr/bin/supervisord"]
