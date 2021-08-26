FROM ubuntu:16.04
SHELL ["/bin/bash", "-c"]

RUN apt update -y

# Install utils
RUN apt install -y \
    vim \
    tmux \
    tree \
    curl \
    screen \
    git

# Install GCC and multilibs to allow x86 compilation
RUN apt install -y build-essential gcc-multilib

# Install Python 2.7
RUN apt install -y python-minimal && curl -L https://bootstrap.pypa.io/pip/2.7/get-pip.py | python2
RUN pip2 install virtualenv

# Bootstrap angr_ctf using Python 2.7
# TODO: Use Python 3.7 once finding a replacement for templite module
ARG ANGR_CTF='/home/angr_ctf'
RUN git clone --depth=1 https://github.com/giladreich/angr_ctf.git $ANGR_CTF
WORKDIR $ANGR_CTF
RUN virtualenv -p /usr/bin/python2 venv && \
    source venv/bin/activate && \
    pip2 install -r requirements.txt && \
    python2 package.py ctfs/

# Installing Python 3.7 in order to get Angr installed.
# Also adding the virtualenv to .bashrc by default in order to have Angr working when
# starting a new terminal session within the container to test things.
RUN apt install -y software-properties-common libffi-dev && add-apt-repository -y ppa:deadsnakes/ppa
RUN apt update && apt install -y python3.7
RUN virtualenv -p /usr/bin/python3.7 venv3
RUN echo "source $(realpath venv3)/bin/activate" >> ~/.bashrc
RUN source $(realpath venv3)/bin/activate && pip3 install angr

WORKDIR $ANGR_CTF/ctfs
