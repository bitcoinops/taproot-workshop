# taproot-workshop

This repo contains the jupyter notebooks for Optech's [Schnorr/Taproot
workshops](https://bitcoinops.org/workshops/#taproot-workshop).

## Introduction

For the purposes of demonstrating the features of schnorr and taproot to the
Bitcoin developer community, we have developed an extended Python library on
top of Pieter Wuille's Taproot Bitcoin Core branch, which provides Python
classes and methods to build more sophisticated Taproot transactions and
various schnorr signature schemes for preliminary evaluation.

Our Taproot/Schnorr library is an extension of the Bitcoin python test
framework, located in the dedicated [Optech Bitcoin Taproot
Branch](https://github.com/bitcoinops/bitcoin/releases/tag/Taproot_V0.1.4).

*Note: This Library is intended for demonstrative and educational purposes only.*

## Warning

Do not run test instances of bitcoind on the same machine that you store your
Bitcoin private keys. These notebooks shouldn't interfere with your
standard bitcoin data directory, but why risk it?

## Background

It will be useful to have some background on schnorr and taproot before running
through the exercises in this repository.

### Schnorr

- **[bip-schnorr](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki)**:
  This technical document proposes a standard for 64-byte Schnorr signatures
  over the elliptic curve secp256k1.
- **[Taproot, and Schnorr, and SIGHASH_NOINPUT, oh
  my!](https://www.youtube.com/watch?v=YSUVRj8iznU)**: video
  about Taproot, Schnorr, and SIGHASH_NOINPUT by Pieter Wuille, author of the
  Schnorr/Taproot proposal. (Note: since the video SIGHASH_NOINPUT is no longer
  grouped with the taproot/schnorr soft fork proposal) ([transcript](https://diyhpl.us/wiki/transcripts/sf-bitcoin-meetup/2018-07-09-taproot-schnorr-signatures-and-sighash-noinput-oh-my/))
- **[Optech Executive Briefing The Next
  Softfork](https://www.youtube.com/watch?v=fDJRy6K_3yo)**: Optech's video
  presentation of the next proposed soft fork.

### Taproot

- **[bip-taproot](https://github.com/sipa/bips/blob/bip-schnorr/bip-taproot.mediawiki)**:
  This technical document proposes a new SegWit version 1 output type, with spending rules based on Taproot, Schnorr signatures, and Merkle branches.
- **[bip-tapscript](https://github.com/sipa/bips/blob/bip-schnorr/bip-tapscript.mediawiki)**: This technical document specifies the semantics of the initial scripting system under bip-taproot.
- **[Bitcoin Optech’s Overview of the Taproot & Tapscript proposed BIPs](https://bitcoinops.org/en/newsletters/2019/05/14/#overview-of-the-taproot--tapscript-proposed-bips)**: Summary of bip-taproot and bip-tapscript.

### Output Descriptors

- **[Support for Output Descriptors in Bitcoin Core](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)**:
  Since Bitcoin Core v0.17, there is support for output descriptors. This is a simple language which can be used to describe collections of output scripts.


## Requirements

#### Clone this (bitcoinops/taproot-workshop) repository

```
$ git clone https://github.com/bitcoinops/taproot-workshop
```

#### Build a taproot-supporting bitcoind

These workbooks require a `bitcoind` built from the [Optech Taproot
V0.1.4 branch](https://github.com/bitcoinops/bitcoin/releases/tag/Taproot_V0.1.4) which
supports schnorr and taproot. 

![workshop_repositories](images/repositories.jpg)

Clone the bitcoinops/bitcoin repository in a separate directory from this
taproot-workshop repository:

```
$ git clone https://github.com/bitcoinops/bitcoin
```

Note the path where you cloned the bitcoinops/bitcoin repository and add it to
the `config.ini` file in your taproot-workshop repository. For example, set:

```
SOURCE_DIRECTORY=/Users/optech/bitcoin
```

Checkout the Optech taproot branch in the bitcoinops/bitcoin repository, which is tagged as `Taproot_V0.1.4`:

```
$ git checkout Taproot_V0.1.4
```

Build the Optech Taproot branch of bitcoind locally. See the build documentation
(`build-xxxx.md`) in the [Bitcoin Core repository docs
directory](https://github.com/bitcoin/bitcoin/tree/master/doc) for additional
documentation on building bitcoind on
[Unix](https://github.com/bitcoin/bitcoin/blob/master/doc/build-unix.md),
[macOS](https://github.com/bitcoin/bitcoin/blob/master/doc/build-osx.md), or
[Windows](https://github.com/bitcoin/bitcoin/blob/master/doc/build-windows.md).

No need to run `bitcoind` or download the mainchain or testnet blockchain. We will 
run in regtest mode and spawn node instances via scripts.

#### Python 3

Verify you have python3 installed:

```
$ python3 --version
```

If not, you should install Python 3.

Linux:

```
$ sudo apt-get install python3
```

macOS (using [homebrew](https://brew.sh/)):

```
$ brew install python3
```

Windows:

- Install using [binary from
  python.org](https://www.python.org/downloads/windows/) as appropriate for
  your system

#### Python Dependencies

This workshop uses some Python dependencies, particularly `jupyter-notebook`. To
keep dependencies local to the project, you should create and activate a
virtual environment. You can skip this step if you're happy to install the
dependencies globally.

Make sure you are in your taproot-workshop repository folder.

```
$ python3 -m venv .venv && source .venv/bin/activate
```

(if you're using the `csh` or `fish` shells, replace `.venv/bin/activate` with
`.venv/bin/activate.csh` or `.venv/bin/activate.fish`)

Install dependencies:

```
$ pip3 install -r requirements.txt
```

Ensure jupyter notebook is installed:

```
$ jupyter notebook --version
```

Jupyter notebook is a handy tool which allow us to run python code directly in
an interactive document like this one. The workshop materials are built
directly with jupyter .ipynb files, which you can open once you have jupyter
installed.

Start jupyter notebook to see exercises:

```
$ jupyter notebook
```

Jupyter will start a notebook server in your terminal, and provide a link for
your browser from which you can interact with notebook files. If your browser
doesn't automatically open the notebook file explorer, click on the link
provided by jupyter notebook server in the terminal.

- Click on the `0.1-test-notebook.ipynb` notebook.
- Verify that `0.1-test-notebook.ipynb` passes all checks.

After you have run the 0.1 example exercises, please also run through the
0.2-elliptic-curve-math.ipynb and 0.3-tagged-hashes.ipynb notebooks and
exercises before the workshop. 

Notebooks 1.x, 2.x, etc will be covered during the workshop. There is no need to
run through those beforehand.

Stop the current running jupyter session using Control-C in the terminal.

After you have finished your jupyter session, you can deactivate the Python
virtual environment with:

```
$ deactivate
```
