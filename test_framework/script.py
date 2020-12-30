#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functionality to build scripts, as well as signature hash functions.

This file is modified from python-bitcoinlib.
"""

from .messages import CTransaction, CTxOut, sha256, hash256, uint256_from_str, ser_uint256, ser_string, CTxInWitness
from .key import ECKey, ECPubKey

import binascii
import hashlib
import itertools
import queue
import struct

from .bignum import bn2vch

MAX_SCRIPT_ELEMENT_SIZE = 520
LOCKTIME_THRESHOLD = 500000000
ANNEX_TAG = 0x50

OPCODE_NAMES = {}

LEAF_VERSION_TAPSCRIPT = 0xc0

DEFAULT_TAPSCRIPT_VER = 0xc0
TAPROOT_VER = 0

def hash160(s):
    return hashlib.new('ripemd160', sha256(s)).digest()


_opcode_instances = []
class CScriptOp(int):
    """A single script opcode"""
    __slots__ = ()

    @staticmethod
    def encode_op_pushdata(d):
        """Encode a PUSHDATA op, returning bytes"""
        if len(d) < 0x4c:
            return b'' + bytes([len(d)]) + d # OP_PUSHDATA
        elif len(d) <= 0xff:
            return b'\x4c' + bytes([len(d)]) + d # OP_PUSHDATA1
        elif len(d) <= 0xffff:
            return b'\x4d' + struct.pack(b'<H', len(d)) + d # OP_PUSHDATA2
        elif len(d) <= 0xffffffff:
            return b'\x4e' + struct.pack(b'<I', len(d)) + d # OP_PUSHDATA4
        else:
            raise ValueError("Data too long to encode in a PUSHDATA op")

    @staticmethod
    def encode_op_n(n):
        """Encode a small integer op, returning an opcode"""
        if not (0 <= n <= 16):
            raise ValueError('Integer must be in range 0 <= n <= 16, got %d' % n)

        if n == 0:
            return OP_0
        else:
            return CScriptOp(OP_1 + n-1)

    def decode_op_n(self):
        """Decode a small integer opcode, returning an integer"""
        if self == OP_0:
            return 0

        if not (self == OP_0 or OP_1 <= self <= OP_16):
            raise ValueError('op %r is not an OP_N' % self)

        return int(self - OP_1+1)

    def is_small_int(self):
        """Return true if the op pushes a small integer to the stack"""
        if 0x51 <= self <= 0x60 or self == 0:
            return True
        else:
            return False

    def __str__(self):
        return repr(self)

    def __repr__(self):
        if self in OPCODE_NAMES:
            return OPCODE_NAMES[self]
        else:
            return 'CScriptOp(0x%x)' % self

    def __new__(cls, n):
        try:
            return _opcode_instances[n]
        except IndexError:
            assert len(_opcode_instances) == n
            _opcode_instances.append(super(CScriptOp, cls).__new__(cls, n))
            return _opcode_instances[n]

# Populate opcode instance table
for n in range(0xff+1):
    CScriptOp(n)


# push value
OP_0 = CScriptOp(0x00)
OP_FALSE = OP_0
OP_PUSHDATA1 = CScriptOp(0x4c)
OP_PUSHDATA2 = CScriptOp(0x4d)
OP_PUSHDATA4 = CScriptOp(0x4e)
OP_1NEGATE = CScriptOp(0x4f)
OP_RESERVED = CScriptOp(0x50)
OP_1 = CScriptOp(0x51)
OP_TRUE=OP_1
OP_2 = CScriptOp(0x52)
OP_3 = CScriptOp(0x53)
OP_4 = CScriptOp(0x54)
OP_5 = CScriptOp(0x55)
OP_6 = CScriptOp(0x56)
OP_7 = CScriptOp(0x57)
OP_8 = CScriptOp(0x58)
OP_9 = CScriptOp(0x59)
OP_10 = CScriptOp(0x5a)
OP_11 = CScriptOp(0x5b)
OP_12 = CScriptOp(0x5c)
OP_13 = CScriptOp(0x5d)
OP_14 = CScriptOp(0x5e)
OP_15 = CScriptOp(0x5f)
OP_16 = CScriptOp(0x60)

# control
OP_NOP = CScriptOp(0x61)
OP_VER = CScriptOp(0x62)
OP_IF = CScriptOp(0x63)
OP_NOTIF = CScriptOp(0x64)
OP_VERIF = CScriptOp(0x65)
OP_VERNOTIF = CScriptOp(0x66)
OP_ELSE = CScriptOp(0x67)
OP_ENDIF = CScriptOp(0x68)
OP_VERIFY = CScriptOp(0x69)
OP_RETURN = CScriptOp(0x6a)

# stack ops
OP_TOALTSTACK = CScriptOp(0x6b)
OP_FROMALTSTACK = CScriptOp(0x6c)
OP_2DROP = CScriptOp(0x6d)
OP_2DUP = CScriptOp(0x6e)
OP_3DUP = CScriptOp(0x6f)
OP_2OVER = CScriptOp(0x70)
OP_2ROT = CScriptOp(0x71)
OP_2SWAP = CScriptOp(0x72)
OP_IFDUP = CScriptOp(0x73)
OP_DEPTH = CScriptOp(0x74)
OP_DROP = CScriptOp(0x75)
OP_DUP = CScriptOp(0x76)
OP_NIP = CScriptOp(0x77)
OP_OVER = CScriptOp(0x78)
OP_PICK = CScriptOp(0x79)
OP_ROLL = CScriptOp(0x7a)
OP_ROT = CScriptOp(0x7b)
OP_SWAP = CScriptOp(0x7c)
OP_TUCK = CScriptOp(0x7d)

# splice ops
OP_CAT = CScriptOp(0x7e)
OP_SUBSTR = CScriptOp(0x7f)
OP_LEFT = CScriptOp(0x80)
OP_RIGHT = CScriptOp(0x81)
OP_SIZE = CScriptOp(0x82)

# bit logic
OP_INVERT = CScriptOp(0x83)
OP_AND = CScriptOp(0x84)
OP_OR = CScriptOp(0x85)
OP_XOR = CScriptOp(0x86)
OP_EQUAL = CScriptOp(0x87)
OP_EQUALVERIFY = CScriptOp(0x88)
OP_RESERVED1 = CScriptOp(0x89)
OP_RESERVED2 = CScriptOp(0x8a)

# numeric
OP_1ADD = CScriptOp(0x8b)
OP_1SUB = CScriptOp(0x8c)
OP_2MUL = CScriptOp(0x8d)
OP_2DIV = CScriptOp(0x8e)
OP_NEGATE = CScriptOp(0x8f)
OP_ABS = CScriptOp(0x90)
OP_NOT = CScriptOp(0x91)
OP_0NOTEQUAL = CScriptOp(0x92)

OP_ADD = CScriptOp(0x93)
OP_SUB = CScriptOp(0x94)
OP_MUL = CScriptOp(0x95)
OP_DIV = CScriptOp(0x96)
OP_MOD = CScriptOp(0x97)
OP_LSHIFT = CScriptOp(0x98)
OP_RSHIFT = CScriptOp(0x99)

OP_BOOLAND = CScriptOp(0x9a)
OP_BOOLOR = CScriptOp(0x9b)
OP_NUMEQUAL = CScriptOp(0x9c)
OP_NUMEQUALVERIFY = CScriptOp(0x9d)
OP_NUMNOTEQUAL = CScriptOp(0x9e)
OP_LESSTHAN = CScriptOp(0x9f)
OP_GREATERTHAN = CScriptOp(0xa0)
OP_LESSTHANOREQUAL = CScriptOp(0xa1)
OP_GREATERTHANOREQUAL = CScriptOp(0xa2)
OP_MIN = CScriptOp(0xa3)
OP_MAX = CScriptOp(0xa4)

OP_WITHIN = CScriptOp(0xa5)

# crypto
OP_RIPEMD160 = CScriptOp(0xa6)
OP_SHA1 = CScriptOp(0xa7)
OP_SHA256 = CScriptOp(0xa8)
OP_HASH160 = CScriptOp(0xa9)
OP_HASH256 = CScriptOp(0xaa)
OP_CODESEPARATOR = CScriptOp(0xab)
OP_CHECKSIG = CScriptOp(0xac)
OP_CHECKSIGVERIFY = CScriptOp(0xad)
OP_CHECKMULTISIG = CScriptOp(0xae)
OP_CHECKMULTISIGVERIFY = CScriptOp(0xaf)

# expansion
OP_NOP1 = CScriptOp(0xb0)
OP_CHECKLOCKTIMEVERIFY = CScriptOp(0xb1)
OP_CHECKSEQUENCEVERIFY = CScriptOp(0xb2)
OP_NOP4 = CScriptOp(0xb3)
OP_NOP5 = CScriptOp(0xb4)
OP_NOP6 = CScriptOp(0xb5)
OP_NOP7 = CScriptOp(0xb6)
OP_NOP8 = CScriptOp(0xb7)
OP_NOP9 = CScriptOp(0xb8)
OP_NOP10 = CScriptOp(0xb9)

# tapscript
OP_CHECKSIGADD = CScriptOp(0xba)

OP_INVALIDOPCODE = CScriptOp(0xff)

OPCODE_NAMES.update({
    OP_0 : 'OP_0',
    OP_PUSHDATA1 : 'OP_PUSHDATA1',
    OP_PUSHDATA2 : 'OP_PUSHDATA2',
    OP_PUSHDATA4 : 'OP_PUSHDATA4',
    OP_1NEGATE : 'OP_1NEGATE',
    OP_RESERVED : 'OP_RESERVED',
    OP_1 : 'OP_1',
    OP_2 : 'OP_2',
    OP_3 : 'OP_3',
    OP_4 : 'OP_4',
    OP_5 : 'OP_5',
    OP_6 : 'OP_6',
    OP_7 : 'OP_7',
    OP_8 : 'OP_8',
    OP_9 : 'OP_9',
    OP_10 : 'OP_10',
    OP_11 : 'OP_11',
    OP_12 : 'OP_12',
    OP_13 : 'OP_13',
    OP_14 : 'OP_14',
    OP_15 : 'OP_15',
    OP_16 : 'OP_16',
    OP_NOP : 'OP_NOP',
    OP_VER : 'OP_VER',
    OP_IF : 'OP_IF',
    OP_NOTIF : 'OP_NOTIF',
    OP_VERIF : 'OP_VERIF',
    OP_VERNOTIF : 'OP_VERNOTIF',
    OP_ELSE : 'OP_ELSE',
    OP_ENDIF : 'OP_ENDIF',
    OP_VERIFY : 'OP_VERIFY',
    OP_RETURN : 'OP_RETURN',
    OP_TOALTSTACK : 'OP_TOALTSTACK',
    OP_FROMALTSTACK : 'OP_FROMALTSTACK',
    OP_2DROP : 'OP_2DROP',
    OP_2DUP : 'OP_2DUP',
    OP_3DUP : 'OP_3DUP',
    OP_2OVER : 'OP_2OVER',
    OP_2ROT : 'OP_2ROT',
    OP_2SWAP : 'OP_2SWAP',
    OP_IFDUP : 'OP_IFDUP',
    OP_DEPTH : 'OP_DEPTH',
    OP_DROP : 'OP_DROP',
    OP_DUP : 'OP_DUP',
    OP_NIP : 'OP_NIP',
    OP_OVER : 'OP_OVER',
    OP_PICK : 'OP_PICK',
    OP_ROLL : 'OP_ROLL',
    OP_ROT : 'OP_ROT',
    OP_SWAP : 'OP_SWAP',
    OP_TUCK : 'OP_TUCK',
    OP_CAT : 'OP_CAT',
    OP_SUBSTR : 'OP_SUBSTR',
    OP_LEFT : 'OP_LEFT',
    OP_RIGHT : 'OP_RIGHT',
    OP_SIZE : 'OP_SIZE',
    OP_INVERT : 'OP_INVERT',
    OP_AND : 'OP_AND',
    OP_OR : 'OP_OR',
    OP_XOR : 'OP_XOR',
    OP_EQUAL : 'OP_EQUAL',
    OP_EQUALVERIFY : 'OP_EQUALVERIFY',
    OP_RESERVED1 : 'OP_RESERVED1',
    OP_RESERVED2 : 'OP_RESERVED2',
    OP_1ADD : 'OP_1ADD',
    OP_1SUB : 'OP_1SUB',
    OP_2MUL : 'OP_2MUL',
    OP_2DIV : 'OP_2DIV',
    OP_NEGATE : 'OP_NEGATE',
    OP_ABS : 'OP_ABS',
    OP_NOT : 'OP_NOT',
    OP_0NOTEQUAL : 'OP_0NOTEQUAL',
    OP_ADD : 'OP_ADD',
    OP_SUB : 'OP_SUB',
    OP_MUL : 'OP_MUL',
    OP_DIV : 'OP_DIV',
    OP_MOD : 'OP_MOD',
    OP_LSHIFT : 'OP_LSHIFT',
    OP_RSHIFT : 'OP_RSHIFT',
    OP_BOOLAND : 'OP_BOOLAND',
    OP_BOOLOR : 'OP_BOOLOR',
    OP_NUMEQUAL : 'OP_NUMEQUAL',
    OP_NUMEQUALVERIFY : 'OP_NUMEQUALVERIFY',
    OP_NUMNOTEQUAL : 'OP_NUMNOTEQUAL',
    OP_LESSTHAN : 'OP_LESSTHAN',
    OP_GREATERTHAN : 'OP_GREATERTHAN',
    OP_LESSTHANOREQUAL : 'OP_LESSTHANOREQUAL',
    OP_GREATERTHANOREQUAL : 'OP_GREATERTHANOREQUAL',
    OP_MIN : 'OP_MIN',
    OP_MAX : 'OP_MAX',
    OP_WITHIN : 'OP_WITHIN',
    OP_RIPEMD160 : 'OP_RIPEMD160',
    OP_SHA1 : 'OP_SHA1',
    OP_SHA256 : 'OP_SHA256',
    OP_HASH160 : 'OP_HASH160',
    OP_HASH256 : 'OP_HASH256',
    OP_CODESEPARATOR : 'OP_CODESEPARATOR',
    OP_CHECKSIG : 'OP_CHECKSIG',
    OP_CHECKSIGVERIFY : 'OP_CHECKSIGVERIFY',
    OP_CHECKMULTISIG : 'OP_CHECKMULTISIG',
    OP_CHECKMULTISIGVERIFY : 'OP_CHECKMULTISIGVERIFY',
    OP_NOP1 : 'OP_NOP1',
    OP_CHECKLOCKTIMEVERIFY : 'OP_CHECKLOCKTIMEVERIFY',
    OP_CHECKSEQUENCEVERIFY : 'OP_CHECKSEQUENCEVERIFY',
    OP_NOP4 : 'OP_NOP4',
    OP_NOP5 : 'OP_NOP5',
    OP_NOP6 : 'OP_NOP6',
    OP_NOP7 : 'OP_NOP7',
    OP_NOP8 : 'OP_NOP8',
    OP_NOP9 : 'OP_NOP9',
    OP_NOP10 : 'OP_NOP10',
    OP_CHECKSIGADD : 'OP_CHECKSIGADD',
    OP_INVALIDOPCODE : 'OP_INVALIDOPCODE',
})

class CScriptInvalidError(Exception):
    """Base class for CScript exceptions"""
    pass

class CScriptTruncatedPushDataError(CScriptInvalidError):
    """Invalid pushdata due to truncation"""
    def __init__(self, msg, data):
        self.data = data
        super(CScriptTruncatedPushDataError, self).__init__(msg)


# This is used, eg, for blockchain heights in coinbase scripts (bip34)
class CScriptNum:
    __slots__ = ("value",)

    def __init__(self, d=0):
        self.value = d

    @staticmethod
    def encode(obj):
        r = bytearray(0)
        if obj.value == 0:
            return bytes(r)
        neg = obj.value < 0
        absvalue = -obj.value if neg else obj.value
        while (absvalue):
            r.append(absvalue & 0xff)
            absvalue >>= 8
        if r[-1] & 0x80:
            r.append(0x80 if neg else 0)
        elif neg:
            r[-1] |= 0x80
        return bytes([len(r)]) + r

    @staticmethod
    def decode(vch):
        result = 0
        # We assume valid push_size and minimal encoding
        value = vch[1:]
        if len(value) == 0:
            return result
        for i, byte in enumerate(value):
            result |= int(byte) << 8*i
        if value[-1] >= 0x80:
            # Mask for all but the highest result bit
            num_mask = (2**(len(value)*8) - 1) >> 1
            result &= num_mask
            result *= -1
        return result


class CScript(bytes):
    """Serialized script

    A bytes subclass, so you can use this directly whenever bytes are accepted.
    Note that this means that indexing does *not* work - you'll get an index by
    byte rather than opcode. This format was chosen for efficiency so that the
    general case would not require creating a lot of little CScriptOP objects.

    iter(script) however does iterate by opcode.
    """
    __slots__ = ()

    @classmethod
    def __coerce_instance(cls, other):
        # Coerce other into bytes
        if isinstance(other, CScriptOp):
            other = bytes([other])
        elif isinstance(other, CScriptNum):
            if (other.value == 0):
                other = bytes([CScriptOp(OP_0)])
            else:
                other = CScriptNum.encode(other)
        elif isinstance(other, int):
            if 0 <= other <= 16:
                other = bytes([CScriptOp.encode_op_n(other)])
            elif other == -1:
                other = bytes([OP_1NEGATE])
            else:
                other = CScriptOp.encode_op_pushdata(bn2vch(other))
        elif isinstance(other, (bytes, bytearray)):
            other = CScriptOp.encode_op_pushdata(other)
        return other

    def __add__(self, other):
        # Do the coercion outside of the try block so that errors in it are
        # noticed.
        other = self.__coerce_instance(other)

        try:
            # bytes.__add__ always returns bytes instances unfortunately
            return CScript(super(CScript, self).__add__(other))
        except TypeError:
            raise TypeError('Can not add a %r instance to a CScript' % other.__class__)

    def join(self, iterable):
        # join makes no sense for a CScript()
        raise NotImplementedError

    def __new__(cls, value=b''):
        if isinstance(value, bytes) or isinstance(value, bytearray):
            return super(CScript, cls).__new__(cls, value)
        else:
            def coerce_iterable(iterable):
                for instance in iterable:
                    yield cls.__coerce_instance(instance)
            # Annoyingly on both python2 and python3 bytes.join() always
            # returns a bytes instance even when subclassed.
            return super(CScript, cls).__new__(cls, b''.join(coerce_iterable(value)))

    def raw_iter(self):
        """Raw iteration

        Yields tuples of (opcode, data, sop_idx) so that the different possible
        PUSHDATA encodings can be accurately distinguished, as well as
        determining the exact opcode byte indexes. (sop_idx)
        """
        i = 0
        while i < len(self):
            sop_idx = i
            opcode = self[i]
            i += 1

            if opcode > OP_PUSHDATA4:
                yield (opcode, None, sop_idx)
            else:
                datasize = None
                pushdata_type = None
                if opcode < OP_PUSHDATA1:
                    pushdata_type = 'PUSHDATA(%d)' % opcode
                    datasize = opcode

                elif opcode == OP_PUSHDATA1:
                    pushdata_type = 'PUSHDATA1'
                    if i >= len(self):
                        raise CScriptInvalidError('PUSHDATA1: missing data length')
                    datasize = self[i]
                    i += 1

                elif opcode == OP_PUSHDATA2:
                    pushdata_type = 'PUSHDATA2'
                    if i + 1 >= len(self):
                        raise CScriptInvalidError('PUSHDATA2: missing data length')
                    datasize = self[i] + (self[i+1] << 8)
                    i += 2

                elif opcode == OP_PUSHDATA4:
                    pushdata_type = 'PUSHDATA4'
                    if i + 3 >= len(self):
                        raise CScriptInvalidError('PUSHDATA4: missing data length')
                    datasize = self[i] + (self[i+1] << 8) + (self[i+2] << 16) + (self[i+3] << 24)
                    i += 4

                else:
                    assert False # shouldn't happen


                data = bytes(self[i:i+datasize])

                # Check for truncation
                if len(data) < datasize:
                    raise CScriptTruncatedPushDataError('%s: truncated data' % pushdata_type, data)

                i += datasize

                yield (opcode, data, sop_idx)

    def __iter__(self):
        """'Cooked' iteration

        Returns either a CScriptOP instance, an integer, or bytes, as
        appropriate.

        See raw_iter() if you need to distinguish the different possible
        PUSHDATA encodings.
        """
        for (opcode, data, sop_idx) in self.raw_iter():
            if data is not None:
                yield data
            else:
                opcode = CScriptOp(opcode)

                if opcode.is_small_int():
                    yield opcode.decode_op_n()
                else:
                    yield CScriptOp(opcode)

    def __repr__(self):
        def _repr(o):
            if isinstance(o, bytes):
                return "x('%s')" % o.hex()
            else:
                return repr(o)

        ops = []
        i = iter(self)
        while True:
            op = None
            try:
                op = _repr(next(i))
            except CScriptTruncatedPushDataError as err:
                op = '%s...<ERROR: %s>' % (_repr(err.data), err)
                break
            except CScriptInvalidError as err:
                op = '<ERROR: %s>' % err
                break
            except StopIteration:
                break
            finally:
                if op is not None:
                    ops.append(op)

        return "CScript([%s])" % ', '.join(ops)

    def GetSigOpCount(self, fAccurate):
        """Get the SigOp count.

        fAccurate - Accurately count CHECKMULTISIG, see BIP16 for details.

        Note that this is consensus-critical.
        """
        n = 0
        lastOpcode = OP_INVALIDOPCODE
        for (opcode, data, sop_idx) in self.raw_iter():
            if opcode in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
                n += 1
            elif opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                if fAccurate and (OP_1 <= lastOpcode <= OP_16):
                    n += opcode.decode_op_n()
                else:
                    n += 20
            lastOpcode = opcode
        return n


SIGHASH_ALL_TAPROOT = 0
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

def FindAndDelete(script, sig):
    """Consensus critical, see FindAndDelete() in Satoshi codebase"""
    r = b''
    last_sop_idx = sop_idx = 0
    skip = True
    for (opcode, data, sop_idx) in script.raw_iter():
        if not skip:
            r += script[last_sop_idx:sop_idx]
        last_sop_idx = sop_idx
        if script[sop_idx:sop_idx + len(sig)] == sig:
            skip = True
        else:
            skip = False
    if not skip:
        r += script[last_sop_idx:]
    return CScript(r)

def IsPayToScriptHash(script):
    return len(script) == 23 and script[0] == OP_HASH160 and script[1] == 20 and script[22] == OP_EQUAL

def IsPayToTaproot(script):
    return len(script) == 34 and script[0] == OP_1 and script[1] == 32

def tagged_hash(tag, data):
    ss = sha256(tag.encode('utf-8'))
    ss += ss
    ss += data
    return sha256(ss)

def GetP2SH(script):
    return CScript([OP_HASH160, hash160(script), OP_EQUAL])

def LegacySignatureHash(script, txTo, inIdx, hashtype):
    """Consensus-correct SignatureHash

    Returns (hash, err) to precisely match the consensus-critical behavior of
    the SIGHASH_SINGLE bug. (inIdx is *not* checked for validity)
    """
    HASH_ONE = b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    if inIdx >= len(txTo.vin):
        return (HASH_ONE, "inIdx %d out of range (%d)" % (inIdx, len(txTo.vin)))
    txtmp = CTransaction(txTo)

    for txin in txtmp.vin:
        txin.scriptSig = b''
    txtmp.vin[inIdx].scriptSig = FindAndDelete(script, CScript([OP_CODESEPARATOR]))

    if (hashtype & 0x1f) == SIGHASH_NONE:
        txtmp.vout = []

        for i in range(len(txtmp.vin)):
            if i != inIdx:
                txtmp.vin[i].nSequence = 0

    elif (hashtype & 0x1f) == SIGHASH_SINGLE:
        outIdx = inIdx
        if outIdx >= len(txtmp.vout):
            return (HASH_ONE, "outIdx %d out of range (%d)" % (outIdx, len(txtmp.vout)))

        tmp = txtmp.vout[outIdx]
        txtmp.vout = []
        for i in range(outIdx):
            txtmp.vout.append(CTxOut(-1))
        txtmp.vout.append(tmp)

        for i in range(len(txtmp.vin)):
            if i != inIdx:
                txtmp.vin[i].nSequence = 0

    if hashtype & SIGHASH_ANYONECANPAY:
        tmp = txtmp.vin[inIdx]
        txtmp.vin = []
        txtmp.vin.append(tmp)

    s = txtmp.serialize_without_witness()
    s += struct.pack(b"<I", hashtype)

    hash = hash256(s)

    return (hash, None)

def get_p2pkh_script(pubkeyhash):
    """Get the script associated with a P2PKH."""
    return CScript([CScriptOp(OP_DUP), CScriptOp(OP_HASH160), pubkeyhash, CScriptOp(OP_EQUALVERIFY), CScriptOp(OP_CHECKSIG)])

# TODO: Allow cached hashPrevouts/hashSequence/hashOutputs to be provided.
# Performance optimization probably not necessary for python tests, however.
# Note that this corresponds to sigversion == 1 in EvalScript, which is used
# for version 0 witnesses.
def SegwitV0SignatureHash(script, txTo, inIdx, hashtype, amount):

    hashPrevouts = 0
    hashSequence = 0
    hashOutputs = 0

    if not (hashtype & SIGHASH_ANYONECANPAY):
        serialize_prevouts = bytes()
        for i in txTo.vin:
            serialize_prevouts += i.prevout.serialize()
        hashPrevouts = uint256_from_str(hash256(serialize_prevouts))

    if (not (hashtype & SIGHASH_ANYONECANPAY) and (hashtype & 0x1f) != SIGHASH_SINGLE and (hashtype & 0x1f) != SIGHASH_NONE):
        serialize_sequence = bytes()
        for i in txTo.vin:
            serialize_sequence += struct.pack("<I", i.nSequence)
        hashSequence = uint256_from_str(hash256(serialize_sequence))

    if ((hashtype & 0x1f) != SIGHASH_SINGLE and (hashtype & 0x1f) != SIGHASH_NONE):
        serialize_outputs = bytes()
        for o in txTo.vout:
            serialize_outputs += o.serialize()
        hashOutputs = uint256_from_str(hash256(serialize_outputs))
    elif ((hashtype & 0x1f) == SIGHASH_SINGLE and inIdx < len(txTo.vout)):
        serialize_outputs = txTo.vout[inIdx].serialize()
        hashOutputs = uint256_from_str(hash256(serialize_outputs))

    ss = bytes()
    ss += struct.pack("<i", txTo.nVersion)
    ss += ser_uint256(hashPrevouts)
    ss += ser_uint256(hashSequence)
    ss += txTo.vin[inIdx].prevout.serialize()
    ss += ser_string(script)
    ss += struct.pack("<q", amount)
    ss += struct.pack("<I", txTo.vin[inIdx].nSequence)
    ss += ser_uint256(hashOutputs)
    ss += struct.pack("<i", txTo.nLockTime)
    ss += struct.pack("<I", hashtype)

    return hash256(ss)

def TaprootSignatureHash(txTo, spent_utxos, hash_type, input_index = 0, scriptpath = False, script = CScript(), codeseparator_pos = -1, annex = None, leaf_ver = LEAF_VERSION_TAPSCRIPT):
    assert (len(txTo.vin) == len(spent_utxos))
    assert (input_index < len(txTo.vin))
    out_type = SIGHASH_ALL if hash_type == 0 else hash_type & 3
    in_type = hash_type & SIGHASH_ANYONECANPAY
    spk = spent_utxos[input_index].scriptPubKey
    ss = bytes([0, hash_type]) # epoch, hash_type
    ss += struct.pack("<i", txTo.nVersion)
    ss += struct.pack("<I", txTo.nLockTime)
    if in_type != SIGHASH_ANYONECANPAY:
        ss += sha256(b"".join(i.prevout.serialize() for i in txTo.vin))
        ss += sha256(b"".join(struct.pack("<q", u.nValue) for u in spent_utxos))
        ss += sha256(b"".join(ser_string(u.scriptPubKey) for u in spent_utxos))
        ss += sha256(b"".join(struct.pack("<I", i.nSequence) for i in txTo.vin))
    if out_type == SIGHASH_ALL:
        ss += sha256(b"".join(o.serialize() for o in txTo.vout))
    spend_type = 0
    if annex is not None:
        spend_type |= 1
    if (scriptpath):
        spend_type |= 2
    ss += bytes([spend_type])
    if in_type == SIGHASH_ANYONECANPAY:
        ss += txTo.vin[input_index].prevout.serialize()
        ss += struct.pack("<q", spent_utxos[input_index].nValue)
        ss += ser_string(spk)
        ss += struct.pack("<I", txTo.vin[input_index].nSequence)
    else:
        ss += struct.pack("<I", input_index)
    if (spend_type & 1):
        ss += sha256(ser_string(annex))
    if out_type == SIGHASH_SINGLE:
        if input_index < len(txTo.vout):
            ss += sha256(txTo.vout[input_index].serialize())
        else:
            ss += bytes(0 for _ in range(32))
    if (scriptpath):
        ss += tagged_hash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
        ss += bytes([0])
        ss += struct.pack("<i", codeseparator_pos)
    assert len(ss) ==  175 - (in_type == SIGHASH_ANYONECANPAY) * 49 - (out_type != SIGHASH_ALL and out_type != SIGHASH_SINGLE) * 32 + (annex is not None) * 32 + scriptpath * 37
    return tagged_hash("TapSighash", ss)

def GetVersionTaggedPubKey(pubkey, version):
    assert pubkey.is_compressed
    assert pubkey.is_valid
    # When the version 0xfe is used, the control block may become indistinguishable from annex.
    # In such case, use of annex becomes mandatory.
    assert version >= 0 and version < 0xff and not (version & 1)
    data = pubkey.get_bytes()
    return bytes([data[0] & 1 | version]) + data[1:]

def taproot_tree_helper(scripts):
    if len(scripts) == 1:
        script = scripts[0]
        if isinstance(script, list):
            return taproot_tree_helper(script)
        version = DEFAULT_TAPSCRIPT_VER
        if isinstance(script, tuple):
            version, script = script
        assert isinstance(script, bytes)
        h = tagged_hash("TapLeaf", bytes([version & 0xfe]) + ser_string(script))
        return ([(version, script, bytes())], h)
    split_pos = len(scripts) // 2
    left, left_h = taproot_tree_helper(scripts[0:split_pos])
    right, right_h = taproot_tree_helper(scripts[split_pos:])
    left = [(version, script, control + right_h) for version, script, control in left]
    right = [(version, script, control + left_h) for version, script, control in right]
    if right_h < left_h:
        right_h, left_h = left_h, right_h
    h = tagged_hash("TapBranch", left_h + right_h)
    return (left + right, h)

def taproot_construct(pubkey, scripts=[]):
    """Construct a tree of taproot spending conditions

    pubkey: an ECPubKey object for the root pubkey
    scripts: a list of items; each item is either:
             - a CScript
             - a (version, CScript) tuple
             - another list of items (with the same structure)

    Returns: script (sPK or redeemScript), tweak, {script:control, ...}
    """
    if len(scripts) == 0:
        return (CScript([OP_1, GetVersionTaggedPubKey(pubkey, TAPROOT_VER)]), bytes([0 for i in range(32)]), {})

    ret, h = taproot_tree_helper(scripts)
    control_map = dict((script, GetVersionTaggedPubKey(pubkey, version) + control) for version, script, control in ret)
    tweak = tagged_hash("TapTweak", pubkey.get_bytes() + h)
    tweaked = pubkey.tweak_add(tweak)
    return (CScript([OP_1, GetVersionTaggedPubKey(tweaked, TAPROOT_VER)]), tweak, control_map)

def is_op_success(o):
    return o == 0x50 or o == 0x62 or o == 0x89 or o == 0x8a or o == 0x8d or o == 0x8e or (o >= 0x7e and o <= 0x81) or (o >= 0x83 and o <= 0x86) or (o >= 0x95 and o <= 0x99) or (o >= 0xbb and o <= 0xfe)

def IsPayToPubkey(script):
    pk = ECPubKey()
    pk.set(script[1:34])
    return pk.is_valid and len(script) == 35 and script[-1] == OP_CHECKSIG

def IsCheckSigAdd(script):
    if script[-1] == OP_EQUAL and isinstance(script[-2], int) and script[-3] == OP_CHECKSIGADD:
        return True
    else:
        return False

def ParseDesc(desc, tag, op, cl):
    op_tag = tag+op
    assert(desc[:len(op_tag)] == op_tag)
    desc = desc[len(op_tag):-1]
    depth = 0
    for t in desc:
        if t == op:
            depth += 1
        if t == cl:
            depth -= 1
    if depth == 0:
        return desc
    else:
        # Malformed descriptor.
        raise Exception

class TapLeaf:
    def __init__(self, desc=None, version=DEFAULT_TAPSCRIPT_VER):
        self.version = version
        self.script = None
        self.miniscript = None
        self.sat = None
        if desc:
            self.from_desc(desc)

    def construct_pk(self, key): #ECPubKey
        pk_node = miniscript.pk(key.get_bytes())
        self._set_miniscript(miniscript.c(pk_node))
        self.desc = TapLeaf._desc_serializer('pk',key.get_bytes().hex())
        return self

    def construct_pk_delay(self, key, delay): #ECPubKey, int
        pk_node = miniscript.pk(key.get_bytes())
        older_node = miniscript.older(delay)
        v_c_pk_node = miniscript.v(miniscript.c(pk_node))
        self._set_miniscript(miniscript.and_v(v_c_pk_node, older_node))
        self.desc = TapLeaf._desc_serializer('pk_delay', key.get_bytes().hex(), str(delay))
        return self

    def construct_pk_hashlock(self, key, data): #ECPubKey, 20B, int
        pk_node = miniscript.pk(key.get_bytes())
        hash_node = miniscript.hash160(data)
        v_c_pk_node = miniscript.v(miniscript.c(pk_node))
        self._set_miniscript(miniscript.and_v(v_c_pk_node, hash_node))
        self.desc = TapLeaf._desc_serializer('pk_hashlock', key.get_bytes().hex(), data.hex())
        return self

    def construct_pk_hashlock_delay(self, key, data, delay): #ECPubKey, 20B, int
        pk_node = miniscript.pk(key.get_bytes())
        older_node = miniscript.older(delay)
        v_hash_node = miniscript.v(miniscript.hash160(data))
        v_c_pk_node = miniscript.v(miniscript.c(pk_node))
        self._set_miniscript(miniscript.and_v(v_c_pk_node, miniscript.and_v(v_hash_node, older_node)))
        self.desc = TapLeaf._desc_serializer('pk_hashlock_delay', key.get_bytes().hex(), data.hex(),str(delay))
        return self

    def construct_csa(self, k, pkv):
        keys_data = [key.get_bytes() for key in pkv]
        thresh_csa_node = miniscript.thresh_csa(k, *keys_data)
        self._set_miniscript(thresh_csa_node)
        keys_string = [data.hex() for data in keys_data]
        self.desc = TapLeaf._desc_serializer('csa', str(k), *keys_string)
        return self

    def construct_csa_delay(self, k, pkv, delay):
        keys_data = [key.get_bytes() for key in pkv]
        thresh_csa_node = miniscript.thresh_csa(k, *keys_data)
        v_thresh_csa_node = miniscript.v(thresh_csa_node)
        older_node = miniscript.older(delay)
        self._set_miniscript(miniscript.and_v(v_thresh_csa_node, older_node))
        keys_string = [data.hex() for data in keys_data]
        self.desc = TapLeaf._desc_serializer('csa_delay', str(k), *keys_string, str(delay))
        return self

    def construct_csa_hashlock(self, k, pkv, data):
        keys_data = [key.get_bytes() for key in pkv]
        thresh_csa_node = miniscript.thresh_csa(k, *keys_data)
        v_thresh_csa_node = miniscript.v(thresh_csa_node)
        hash_node = miniscript.hash160(data)
        self._set_miniscript(miniscript.and_v(v_thresh_csa_node, hash_node))
        keys_string = [data.hex() for data in keys_data]
        self.desc = TapLeaf._desc_serializer('csa_hashlock', str(k), *keys_string, data.hex())
        return self

    def construct_csa_hashlock_delay(self, k, pkv, data, delay):
        keys_data = [key.get_bytes() for key in pkv]
        thresh_csa_node = miniscript.thresh_csa(k, *keys_data)
        v_thresh_csa_node = miniscript.v(thresh_csa_node)
        hash_node = miniscript.hash160(data)
        v_hash_node = miniscript.v(hash_node)
        older_node = miniscript.older(delay)
        self._set_miniscript(miniscript.and_v(v_thresh_csa_node, miniscript.and_v(v_hash_node, older_node)))
        keys_string = [data.hex() for data in keys_data]
        self.desc = TapLeaf._desc_serializer('csa_hashlock_delay', str(k), *keys_string, data.hex(),str(delay))
        return self

    def _set_miniscript(self, miniscript):
        self.miniscript = miniscript
        self.script = CScript(self.miniscript.script)
        self.sat = self.miniscript.sat_xy

    @staticmethod
    def _desc_serializer(tag, *args):
        desc = 'ts(' + tag + '('
        for arg in args[:-1]:
            desc += arg + ','
        desc += args[-1] + '))'
        return desc

    def from_desc(self,string):
        string = ''.join(string.split())
        tss = ParseDesc(string, 'ts', '(',')')

        if tss[:3] == 'pk(':
            expr_s = ParseDesc(tss, 'pk' ,'(' ,')')
            args = self._param_parser(expr_s)
            pk = ECPubKey()
            pk.set(bytes.fromhex(args[0]))
            self.construct_pk(pk)

        elif tss[:8] == 'pk_delay(':
            expr_s = ParseDesc(tss, 'pk_delay' ,'(' ,')')
            args = self._param_parser(expr_s)
            pk = ECPubKey()
            pk.set(bytes.fromhex(args[0]))
            self.construct_pk_delay(pk, int(args[1]))

        elif tss[:7] == 'pk_hashlock(':
            expr_s = ParseDesc(tss, 'pk_hashlock' ,'(' ,')')
            args = self._param_parser(expr_s)
            pk = ECPubKey()
            pk.set(bytes.fromhex(args[0]))
            data = bytes.fromhex(args[1])
            self.construct_pk_hashlock(pk, data)

        elif tss[:12] == 'pk_hashlock_delay(':
            expr_s = ParseDesc(tss, 'pk_hashlock_delay' ,'(' ,')')
            args = self._param_parser(expr_s)
            pk = ECPubKey()
            pk.set(bytes.fromhex(args[0]))
            data = bytes.fromhex(args[1])
            self.construct_pk_hashlock_delay(pk, data, int(args[2]))

        elif tss[:4] == 'csa(':
            expr_s = ParseDesc(tss, 'csa' ,'(' ,')')
            args = self._param_parser(expr_s)
            k = int(args[0])
            pkv = []
            for key_string in args[1:]:
                pk = ECPubKey()
                pk.set(bytes.fromhex(key_string))
                pkv.append(pk)
            self.construct_csa(k, pkv)

        elif tss[:9] == 'csa_delay(':
            expr_s = ParseDesc(tss, 'csa_delay' ,'(' ,')')
            args = self._param_parser(expr_s)
            k = int(args[0])
            pkv = []
            for key_string in args[1:-1]:
                pk = ECPubKey()
                pk.set(bytes.fromhex(key_string))
                pkv.append(pk)
            delay = int(args[-1])
            self.construct_csa_delay(k, pkv, delay)

        elif tss[:8] == 'csa_hashlock(':
            expr_s = ParseDesc(tss, 'csa_hashlock' ,'(' ,')')
            args = self._param_parser(expr_s)
            k = int(args[0])
            pkv = []
            for key_string in args[1:-1]:
                pk = ECPubKey()
                pk.set(bytes.fromhex(key_string))
                pkv.append(pk)
            data = bytes.fromhex(args[-1])
            self.construct_csa_hashlock(k, pkv, data)

        elif tss[:13] == 'csa_hashlock_delay(':
            expr_s = ParseDesc(tss, 'csa_hashlock_delay' ,'(' ,')')
            args = self._param_parser(expr_s)
            k = int(args[0])
            pkv = []
            for key_string in args[1:-2]:
                pk = ECPubKey()
                pk.set(bytes.fromhex(key_string))
                pkv.append(pk)
            data = bytes.fromhex(args[-2])
            delay = int(args[-1])
            self.construct_csa_hashlock_delay(k, pkv, data, delay)

        elif tss[:4] =='raw(':
            self.script = CScript(binascii.unhexlify(tss[4:-1]))

        else:
            raise Exception('Tapscript descriptor not recognized.')

    @staticmethod
    def _param_parser(expr_string):
        args = []
        idx_ = 0
        expr_string_ = expr_string
        for idx, ch in enumerate(expr_string):
            if ch == ',':
                args.append(expr_string[idx_:idx])
                idx_ = idx+1
                expr_string_ = expr_string[idx_:]
        args.append(expr_string_)
        return args

    def tagged_hash(self):
        return tagged_hash("TapLeaf", bytes([self.version & 0xfe]) + ser_string(self.script))

    def __lt__(self, other):
        return self.tagged_hash() < other.tagged_hash()

    def __gt__(self, other):
        return self.tagged_hash() > other.tagged_hash()

    @staticmethod
    def generate_threshold_csa(k, pubkeys):
        if k == 1 or len(pubkeys) <= k:
            raise Exception
        pubkeys_b = [pubkey.get_bytes() for pubkey in pubkeys]
        pubkeys_b.sort()
        pubkey_b_sets = list(itertools.combinations(iter(pubkeys_b), k))
        tapscripts = []
        for pubkey_b_set in pubkey_b_sets:
            pubkey_set = []
            for pubkey_b in pubkey_b_set:
                pk = ECPubKey()
                pk.set(pubkey_b)
                pubkey_set.append(pk)
            tapscript = TapLeaf()
            tapscript.construct_csa(k, pubkey_set)
            tapscripts.append(tapscript)
        return tapscripts

class TapTree:
    def __init__(self, *, key=None, root=None):
        """Taptree constructor. Takes an optional `key` ECPubKey and `root` Tapbranch."""
        self.key = key if key else ECPubKey()
        self.root = root if root else Tapbranch()

    def from_desc(self, desc):
        desc = ''.join(desc.split())
        pk = ECPubKey()
        pk.set(binascii.unhexlify(desc[3:69]))
        if len(desc)>71 and desc[:3] == 'tp(' and pk.is_valid and desc[69] == ',' and desc[-1] == ')':
            self.key = pk
            self._decode_tree(desc[70:-1], parent=self.root)
        else:
            raise Exception
        return self

    # Tree construction from list(weight(int), TapScript)
    def huffman_constructor(self, tuple_list):
        p = queue.PriorityQueue()
        for weight_tapleaf in tuple_list:
            p.put(weight_tapleaf)
        while p.qsize() > 1:
            l, r = p.get(), p.get()
            node = Tapbranch(l[1], r[1])
            p.put((l[0]+r[0], node))
        self.root = p.get()[1]

    def set_key(self, data):
        self.key.set(data)

    @property
    def desc(self):
        assert self.key.valid == True, "Valid internal key must be set."
        res = 'tp(' +  self.key.get_bytes().hex() + ','
        res += TapTree._encode_tree(self.root)
        res += ')'
        return res

    def construct(self):
        assert self.key.valid == True, "Valid internal key must be set."
        ctrl, h = self._constructor(self.root)
        tweak = tagged_hash("TapTweak", self.key.get_bytes() + h)
        control_map = dict((script, GetVersionTaggedPubKey(self.key, version) + control) for version, script, control in ctrl)
        tweaked = self.key.tweak_add(tweak)
        return (CScript([OP_1, GetVersionTaggedPubKey(tweaked, TAPROOT_VER)]), tweak, control_map)

    @staticmethod
    def _constructor(node):
        if isinstance(node, TapLeaf):
            h = node.tagged_hash()
            ctrl = [(node.version, node.script, bytes())]
            return ctrl, h
        if isinstance(node.left, TapLeaf):
            h_l = node.left.tagged_hash()
            ctrl_l = [(node.left.version, node.left.script, bytes())]
        else:
            ctrl_l, h_l  = TapTree._constructor(node.left)
        if isinstance(node.right, TapLeaf):
            h_r = node.right.tagged_hash()
            ctrl_r = [(node.right.version, node.right.script, bytes())]
        else:
            ctrl_r, h_r = TapTree._constructor(node.right)

        ctrl_l = [(version, script, ctrl + h_r) for version, script, ctrl in ctrl_l]
        ctrl_r = [(version, script, ctrl + h_l) for version, script, ctrl in ctrl_r]
        if h_r < h_l:
            h_r, h_l = h_l, h_r
        h = tagged_hash("TapBranch", h_l + h_r)
        return (ctrl_l + ctrl_r , h)

    @staticmethod
    def _encode_tree(node):
        string = '['
        if isinstance(node, TapLeaf):
            string += node.desc
            string += ']'
            return string
        if isinstance(node.left, TapLeaf):
            string += node.left.desc
        else:
            string += TapTree._encode_tree(node.left)
        string += ','
        if isinstance(node.right, TapLeaf):
            string += node.right.desc
        else:
            string += TapTree._encode_tree(node.right)
        string += ']'
        return string

    def _decode_tree(self, string, parent=None):
        l, r = TapTree._parse_tuple(string)
        if not r:
            self.root = TapLeaf()
            self.root.from_desc(l)
            return
        if (l[0] == '[' and l[-1] == ']'):
            parent.left = Tapbranch()
            self._decode_tree(l, parent=parent.left)
        else:
            parent.left = TapLeaf()
            parent.left.from_desc(l)
        if (r[0] == '[' and r[-1] == ']'):
            parent.right = Tapbranch()
            self._decode_tree(r, parent=parent.right)
        else:
            parent.right = TapLeaf()
            parent.right.from_desc(r)

    @staticmethod
    def _parse_tuple(ts):
        ts = ts[1:-1]
        depth = 0
        l, r = None, None
        for idx, ch in enumerate(ts):
            if depth == 0 and ch == ',':
                l,r = ts[:idx], ts[idx+1:]
                break
            if ch == '[' or ch == '(':
                depth += 1
            if ch == ']' or ch == ')':
                depth -= 1
        if depth == 0 and (l and r):
            return l, r
        elif depth == 0:
            return ts, ''
        else:
            # Malformed tuple.
            raise Exception

class Tapbranch():
    # Internal Taptree branch.
    def __init__(self, left=None, right=None):
        self.left = left
        self.right = right

    def tagged_hash(self):
        return tagged_hash("TapBranch", b''.join(sorted([self.left.tagged_hash(),self.right.tagged_hash()])))

    def __lt__(self, other):
        return self.tagged_hash() < other.tagged_hash()

    def __gt__(self, other):
        return self.tagged_hash() > other.tagged_hash()

# Miniscript Node.
class node_type:
    def __init__(self, script=False, nsat=False, sat_xy=False, sat_z=False, typ=False, corr=False, mal=False, children=False, childnum=None):
        self._script = script
        self._nsat = nsat
        self._sat_xy = sat_xy
        self._sat_z= sat_z
        self._typ = typ
        self._corr = corr
        self._mal = mal
        self.children = children # [x,y,z]

        # Assert all corr/mal/child members are defined.
        assert(all (key in corr(children).keys() for key in ('z','o','n','d','u')))
        for _ , value in vars(self).items():
            assert(value != None)
        # assert(len(children)==3) # This doesn't hold with threshold.

    def __getattr__(self,name):
        attr = getattr(self, '_'+name)
        if attr != None:
            # All lambda's must accept children argument.
            return attr(self.children)
        else:
            return None

# Factory class to generate miniscript nodes.
class miniscript:
    @staticmethod
    def decode(string):
        tag, exprs = miniscript._parse(string)

        # Return terminal expressions:
        # ['pk','pk_h','older','after','sha256','hash256','hash160','hash160','1','0']:
        if tag in ['pk','pk_h', 'older', 'hash160', 'thresh_csa']:

            if tag in ['pk', 'pk_h']:
                key_b = bytes.fromhex(exprs[0])
                return getattr(miniscript, tag)(key_b)

            elif tag in ['older']:
                n = int(exprs[0])
                return getattr(miniscript, tag)(n)

            elif tag in ['hash160']:
                digest = bytes.fromhex(exprs[0])
                return getattr(miniscript, tag)(digest)

            elif tag in ['thresh_csa']:
                k = int(exprs[0])
                keys = []
                for key_string in exprs[1:]:
                    key_data = bytes.fromhex(key_string)
                    keys.append(key_data)
                return getattr(miniscript, tag)(k, *keys)

        child_nodes = []
        for expr in exprs:
            child_nodes.append(miniscript.decode(expr))
        return getattr(miniscript, tag)(*child_nodes)

    @staticmethod
    def _parse(string):
        # TODO: Handle single arg case.
        string = ''.join(string.split())
        depth = 0
        tag = ''
        exprs = []
        for idx, ch in enumerate(string):
            if ch == ':' and depth == 0:
                return string[:idx], [string[idx+1:]]
            if ch == '(':
                depth += 1
                if depth == 1:
                    tag = string[:idx]
                    prev_idx = idx
            if ch == ')':
                depth -= 1
                if depth == 0:
                    exprs.append(string[prev_idx+1:idx])
            if depth == 1 and ch == ',':
                exprs.append(string[prev_idx+1:idx])
                prev_idx = idx
        if depth == 0 and bool(tag) and bool(exprs):
            return tag, exprs
        else:
            raise Exception('Malformed miniscript string.')

    @staticmethod
    def pk(key):
        assert((key[0] in [0x02, 0x03]) or (key[0] not in [0x04, 0x06, 0x07]))
        assert(len(key) == 33)
        script = lambda x: [key]
        nsat = lambda x: [0]
        sat_xy = lambda x: [('sig', key)]
        sat_z = lambda x: [False]
        typ = lambda x: 'K' # Only one possible.
        corr = lambda x: {'z': False,'o': True, 'n': True, 'd': True, 'u': True}
        mal = lambda x: {'e': True,'f': False, 'm': True, 's': True}
        children = [None, None, None] # Terminal.
        return node_type(script=script, nsat=nsat, sat_xy=sat_xy, sat_z=sat_z,  typ=typ, corr=corr, mal=mal,children=children)

    @staticmethod
    def older(n):
        assert(n >= 1 and n < 2**32)
        script = lambda x: [CScriptNum(n), OP_CHECKSEQUENCEVERIFY]
        nsat = lambda x: [False]
        sat_xy = lambda x: []
        sat_z = lambda x: [False]
        typ = lambda x: 'B'
        corr = lambda x: {'z': True,'o': False, 'n': False, 'd': False, 'u': False}
        mal = lambda x: {'e': False,'f': True, 'm': True, 's': False}
        children = [None, None, None] # Terminal.
        return node_type(script=script, nsat=nsat, sat_xy=sat_xy, sat_z=sat_z,  typ=typ, corr=corr, mal=mal,children=children)

    @staticmethod
    def hash160(data):
        assert(len(data) == 20)
        script = lambda x: [OP_SIZE, CScriptNum(32), OP_EQUALVERIFY, OP_HASH160, data, OP_EQUAL]
        nsat = lambda x: [b'\x00'*32] # Not non-malleably.
        sat_xy = lambda x: [('preimage', data)]
        sat_z = lambda x: [False]
        typ = lambda x: 'B'
        corr = lambda x: {'z': False,'o': True, 'n': True, 'd': True, 'u': True}
        mal = lambda x: {'e': False,'f': False, 'm': True, 's': False}
        children = [None, None, None] # Terminal.
        return node_type(script=script, nsat=nsat, sat_xy=sat_xy, sat_z=sat_z,  typ=typ, corr=corr, mal=mal,children=children)

    @staticmethod
    def c(expr):
        script = lambda x: x[0].script + [OP_CHECKSIG]
        nsat = lambda x: x[0].nsat
        sat_xy = lambda x: x[0].sat_xy
        sat_z = lambda x: [False]
        typ = lambda x: 'B' if x[0].typ == 'K' else False
        corr = lambda x: {'z': False,'o': x[0].corr['o'], 'n': x[0].corr['n'], 'd': x[0].corr['d'], 'u': True}
        mal = lambda x: {'f': False, 'e': x[0].mal['e'], 'm': x[0].mal['m'], 's': x[0].mal['s']}
        children = [expr, None, None]
        return node_type(script=script, nsat=nsat, sat_xy=sat_xy, sat_z=sat_z,  typ=typ, corr=corr, mal=mal,children=children)

    @staticmethod
    def v(expr):
        script = lambda x: x[0].script + [OP_VERIFY]
        nsat = lambda x: [False]
        sat_xy = lambda x: x[0].sat_xy
        sat_z = lambda x: [False]
        typ = lambda x: 'V' if x[0].typ == 'B' else False
        corr = lambda x: {'z': x[0].corr['z'],'o': x[0].corr['o'], 'n': x[0].corr['n'], 'd': False, 'u': False}
        mal = lambda x: {'f': True, 'e': False, 'm': x[0].mal['m'], 's': x[0].mal['s']}
        children = [expr, None, None]
        return node_type(script=script, nsat=nsat, sat_xy=sat_xy, sat_z=sat_z,  typ=typ, corr=corr, mal=mal,children=children)

    @staticmethod
    def and_v(expr_l, expr_r):
        script = lambda x: x[0].script + x[1].script
        nsat = lambda x: [False]
        sat_xy = lambda x: x[1].sat_xy + x[0].sat_xy
        sat_z = lambda x: [False]
        typ = lambda x:\
            'B' if (x[0].typ == 'V' and x[1].typ == 'B') else\
            'K' if (x[0].typ == 'V' and x[1].typ == 'K') else\
            'V' if (x[0].typ == 'V' and x[1].typ == 'V') else False
        corr = lambda x: {\
            'z': bool(x[0].corr['z']*x[1].corr['z']),\
            'o': bool(x[0].corr['z']*x[1].corr['o']+x[0].corr['o']*x[1].corr['z']),\
            'n': bool(x[0].corr['n']+x[0].corr['z']*x[1].corr['n']),\
            'd': False,\
            'u': False}
        mal = lambda x: {\
            'f': bool(x[0].mal['f']*x[1].mal['f']),\
            'e': False,\
            'm':bool(x[0].mal['m']*x[1].mal['m']),\
            's': bool(x[0].mal['s']+x[1].mal['s'])}
        children = [expr_l, expr_r, None]
        return node_type(script=script, nsat=nsat, sat_xy=sat_xy, sat_z=sat_z,  typ=typ, corr=corr, mal=mal,children=children)

    @staticmethod # TODO:
    def thresh_csa(k, *args): #arg[0] = k, arg[i>0] = expr_i
        assert(k > 0 and k <= len(args) and len(args) > 1) # Requires more than 1 pk.
        for key in args:
            assert(len(key) == 33)
            assert(key[0] in [0x02, 0x03]) or (key[0] not in [0x04, 0x06, 0x07])
        script = lambda x: [args[0], OP_CHECKSIG] + list(itertools.chain.from_iterable([[args[i], OP_CHECKSIGADD] for i in range(1,len(args))])) + [k, OP_NUMEQUAL]
        nsat = lambda x: [0x00]*len(args)
        sat_xy = lambda x: [('sig', args[i]) for i in range(0,len(args))][::-1] # TODO: ('thresh(n)', [('sig', (0x02../0x00)), ('sig', (0x02../0x00))])
        sat_z = lambda x: [False]
        typ = lambda x: 'B'
        corr = lambda x: {'z': False,'o': False, 'n': False, 'd': True, 'u': True}
        mal = lambda x: {'f': False, 'e': True, 'm': True, 's': True}
        children = [None, None, None] # Terminal expression.
        return node_type(script=script, nsat=nsat, sat_xy=sat_xy, sat_z=sat_z,  typ=typ, corr=corr, mal=mal,children=children)
