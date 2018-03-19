# Pull base image
FROM ubuntu:16.04

# Install essential packages

RUN rm -rf /var/lib/apt/lists/*
RUN apt-get -y update
RUN apt-get -y upgrade

# for folly
RUN apt-get install -y cmake libboost-all-dev libevent-dev libdouble-conversion-dev libgoogle-glog-dev
RUN apt-get install -y libgflags-dev libiberty-dev liblz4-dev liblzma-dev libsnappy-dev make
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get install -y zlib1g-dev binutils-dev libjemalloc-dev libssl-dev pkg-config

# for storage layer
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get install -y software-properties-common
RUN add-apt-repository -y ppa:jonathonf/gcc-7.2
RUN apt-get -y update
RUN apt-get install -y gcc-7 g++-7
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 60 --slave /usr/bin/g++ g++ /usr/bin/g++-7

ADD run.sh /opt/run.sh

VOLUME /shared
WORKDIR /shared
RUN chmod +x /opt/run.sh
CMD ["/opt/run.sh"]
