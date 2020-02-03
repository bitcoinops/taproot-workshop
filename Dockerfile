FROM ubuntu:18.04
MAINTAINER satoshi

RUN apt-get update -qq && apt-get install -y \
    git \
    wget \
    build-essential \
    libtool \
    autotools-dev \
    automake \
    pkg-config \
    libssl-dev \
    libevent-dev \
    bsdmainutils \
    python3 \
    libboost-all-dev \
    vim \
    python3-pip

# Checkout bitcoin source
RUN mkdir /optech
WORKDIR /optech
RUN git clone https://github.com/bitcoinops/taproot-workshop
RUN git clone https://github.com/bitcoinops/bitcoin && cd ./bitcoin && git checkout Taproot_V0.1.4

# Install Berkley Database
RUN wget http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz
RUN tar -xvf db-4.8.30.NC.tar.gz
WORKDIR /optech/db-4.8.30.NC/build_unix
RUN mkdir -p build
RUN BDB_PREFIX=$(pwd)/build
RUN ../dist/configure --disable-shared --enable-cxx --with-pic --prefix=$BDB_PREFIX
RUN make install

# install bitcoin
WORKDIR /optech/bitcoin
RUN ./autogen.sh
RUN ./configure CPPFLAGS="-I${BDB_PREFIX}/include/ -O2" LDFLAGS="-L${BDB_PREFIX}/lib/" --without-gui
RUN make
RUN make install

# configure bitcoin network
ARG NETWORK=regtest
ARG RPC_USER=foo
ARG RPC_PASSWORD=bar
RUN mkdir -p ~/.bitcoin
RUN rpcuser="rpcuser=${RPC_USER}" && \
    rpcpassword="rpcpassword=${RPC_PASSWORD}" && \
    network="${NETWORK}=1" && \
    rpcport="rpcport=8332" && \
    rpcallowip="rpcallowip=127.0.0.1" && \
    rpcconnect="rpcconnect=127.0.0.1" && \
    echo "$rpcuser\n$rpcpassword\n$network\n$rpcport\n$rpcallowip\n$rpcconnect" > /root/.bitcoin/bitcoin.conf

WORKDIR /optech/taproot-workshop
RUN sed -i.bak 's\^SOURCE_DIRECTORY=\SOURCE_DIRECTORY=/optech/bitcoin\g' config.ini
RUN pip3 install -r requirements.txt

ENTRYPOINT ["jupyter", "notebook", "--allow-root", "--ip=0.0.0.0", "--no-browser"]
