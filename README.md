# taproot-workshop

This repo contains the Jupyter notebooks for Optech's [Schnorr/Taproot
workshops](https://bitcoinops.org/workshops/#taproot-workshop).

## Introduction

For the purposes of demonstrating the features of Schnorr and Taproot to the
Bitcoin developer community, we have developed an extended Python library on
top of Pieter Wuille's Taproot Bitcoin Core branch, which provides Python
classes and methods to build more sophisticated Taproot transactions and
various Schnorr signature schemes for preliminary evaluation.

Our Taproot/Schnorr library is an extension of the Bitcoin python test
framework, located in the dedicated [Optech Bitcoin Taproot
Branch](https://github.com/bitcoinops/bitcoin/releases/tag/v0.1).

![fct_test_library](files/taproot_library_introduction0.jpg)

*Note: This Library is intended for demonstrative and educational purposes only.*

## Warning

Do not run test instances of bitcoind on the same machine that you store your
Bitcoin private keys. These notebooks shouldn't interfere with your
standard bitcoin data directory directory, but why risk it?

## Requirements

#### bitcoind

These workbooks require the [Optech Taproot
branch](https://github.com/bitcoinops/bitcoin/releases/tag/v0.1). To use the
workbooks, you should:

- Checkout the Optech Taproot branch.
- Build the Optech Taproot branch of bitcoind locally. See the build
  documentation (`build-xxxx.md`) in the [Bitcoin Core repository docs
  directory](https://github.com/bitcoin/bitcoin/tree/master/doc) for additional
  documentation on building bitcoind.
- Verify that the test workbook passes FIXME: add link to test workbook.

#### Python Dependencies

To keep dependencies local to the project, you should create and activate a
virtual environment. You can skip this step if you're happy to install the
dependencies globally:

```
$ python3 -m venv .venv && source .venv/bin/activate
```

Install dependencies:

```
$ pip3 install -r requirements.txt
```

(after you have finished your Jupyter session, you can deactivate
the virtual environment with:

```
deactivate
```
)

## Start Jupyter notebook to see exercises

```
$ jupyter-notebook
```
