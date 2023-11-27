# Use an official Python runtime as a parent image
# FROM python:3.8
ARG LINUX_DISTRO=ubuntu:latest
ARG PYTHON_VERSION=3.8

FROM ${LINUX_DISTRO}
# Set the working directory in the container

RUN apt-get update -y
RUN apt-get install -y zip
RUN pip install pytest
RUN chmod u+s $(which find)
RUN useradd -ms /bin/bash lowpriv



USER lowpriv

WORKDIR /home/lowpriv/
COPY --chown=lowpriv:lowpriv . .

# Run pytest when the container launches
# CMD ["pytest", "-v"]
CMD ["pytest", "-v"]