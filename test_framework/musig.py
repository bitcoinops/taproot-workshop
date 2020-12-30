# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Preliminary MuSig implementation.

WARNING: This code is slow, uses bad randomness, does not properly protect
keys, and is trivially vulnerable to side channel attacks. Do not use for
anything but tests.

See https://eprint.iacr.org/2018/068.pdf for the MuSig signature scheme implemented here.
"""

import hashlib

from .key import (
    SECP256K1,
    SECP256K1_ORDER,
    TaggedHash,
)

def generate_musig_key(pubkey_list):
    """Aggregate individually generated public keys.

    Returns a MuSig public key as defined in the MuSig paper."""
    pubkey_list_sorted = sorted([int.from_bytes(key.get_bytes(), 'big') for key in pubkey_list])
    L = b''
    for px in pubkey_list_sorted:
        L += px.to_bytes(32, 'big')
    Lh = hashlib.sha256(L).digest()
    musig_c = {}
    aggregate_key = 0
    for key in pubkey_list:
        musig_c[key] = hashlib.sha256(Lh + key.get_bytes()).digest()
        aggregate_key += key.mul(musig_c[key])
    return musig_c, aggregate_key

def aggregate_schnorr_nonces(nonce_point_list):
    """Construct aggregated musig nonce from individually generated nonces."""
    R_agg = sum(nonce_point_list)
    R_agg_affine = SECP256K1.affine(R_agg.p)
    negated = False
    if R_agg_affine[1] % 2 != 0:
        negated = True
        R_agg_negated = SECP256K1.mul([(R_agg.p, SECP256K1_ORDER - 1)])
        R_agg.p = R_agg_negated
    return R_agg, negated

def sign_musig(priv_key, k_key, R_musig, P_musig, msg):
    """Construct a MuSig partial signature and return the s value."""
    assert priv_key.valid
    assert priv_key.compressed
    assert P_musig.compressed
    assert len(msg) == 32
    assert k_key is not None and k_key.secret != 0
    assert R_musig.get_y() % 2 == 0
    e = musig_digest(R_musig, P_musig, msg)
    return (k_key.secret + e * priv_key.secret) % SECP256K1_ORDER

def musig_digest(R_musig, P_musig, msg):
    """Get the digest to sign for musig"""
    return int.from_bytes(TaggedHash("BIP0340/challenge", R_musig.get_bytes() + P_musig.get_bytes() + msg), 'big') % SECP256K1_ORDER

def aggregate_musig_signatures(s_list, R_musig):
    """Construct valid Schnorr signature from a list of partial MuSig signatures."""
    assert s_list is not None and all(isinstance(s, int) for s in s_list)
    s_agg = sum(s_list) % SECP256K1_ORDER
    return R_musig.get_x().to_bytes(32, 'big') + s_agg.to_bytes(32, 'big')
