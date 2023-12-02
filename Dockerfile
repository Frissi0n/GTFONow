# Use an official Python runtime as a parent image
# FROM python:3.8
ARG LINUX_DISTRO=ubuntu:latest
ARG PYTHON_VERSION=3.8

FROM python:${PYTHON_VERSION}
# Set the working directory in the container

RUN apt-get update -y
RUN apt-get install -y zip 
RUN apt-get install -y cron
RUN apt-get install -y nano
RUN apt-get install -y nmap
RUN apt-get install -y vim
RUN apt-get install -y supervisor
RUN apt-get install -y openssh-server
RUN apt-get install -y sudo
RUN pip install pytest pytest-cov
RUN chmod u+s $(which find)
RUN chmod u+s $(which nmap)
RUN chmod u+s $(which cp)
RUN chmod u+s $(which tee)
RUN chmod u+s $(which dd)
RUN chmod u+s $(which mv)
RUN chmod u+s $(which rbash)

RUN useradd -ms /bin/bash lowpriv
RUN useradd -ms /bin/bash higherpriv

RUN echo "lowpriv ALL=(ALL) NOPASSWD: /usr/bin/head" >> /etc/sudoers
RUN echo "lowpriv ALL=(higherpriv) NOPASSWD: /usr/bin/vim" >> /etc/sudoers

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN mkdir /run/sshd
# USER lowpriv

WORKDIR /home/lowpriv/
COPY --chown=lowpriv:lowpriv . .


CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

#CMD ["pytest", "-v"]
