#!/bin/bash

set -ue

# Check if script is run inside Google Colab.
[ -z "$COLAB_GPU" ] && echo "Exiting: Seems like you are not running this script inside Google Colab." && exit 1;

# Load the custom `bitcoind` binary.
wget -q -O colab-binary.tar.xz https://github.com/bitcoinops/bitcoin/releases/download/Taproot_V0.1.4/colab-binary.tar.xz
tar xf colab-binary.tar.xz
chmod +x bitcoind
mkdir -p /content/bitcoin/src
mv bitcoind /content/bitcoin/src

# Setup the functional test config.ini.
mkdir -p /content/bitcoin/test
cat >/content/bitcoin/test/config.ini <<EOL
# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# These environment variables are set by the build process and read by
# test/functional/test_runner.py and test/util/bitcoin-util-test.py

[environment]
PACKAGE_NAME=Bitcoin Core
SRCDIR=/content/bitcoin
BUILDDIR=/content/bitcoin
EXEEXT=
RPCAUTH=/content/bitcoin/share/rpcauth/rpcauth.py

[components]
# Which components are enabled. These are commented out by configure if they were disabled when running config.
#ENABLE_WALLET=true
#ENABLE_CLI=true
ENABLE_BITCOIND=true
#ENABLE_FUZZ=true
ENABLE_ZMQ=true
EOL


# Clone the Optech Taproot Workshop and setup the config.ini + enviroment.
git clone -q https://github.com/bitcoinops/taproot-workshop.git
cp /content/taproot-workshop/util.py /content
cp /content/taproot-workshop/requirements.txt /content
cp /content/taproot-workshop/config.ini /content
cp -r /content/taproot-workshop/test_framework /content
sed -i '$ d' /content/config.ini
echo "SOURCE_DIRECTORY=/content/bitcoin/" >> /content/config.ini
pip3 install -r /content/requirements.txt > /dev/null

echo "Colab environment setup."
