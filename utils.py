from base64 import b64encode, b64decode
from fastecdsa import keys, curve
import hashlib
from binascii import unhexlify
from ecdsa.util import sigencode_der
from ecdsa import SigningKey, SECP256k1


def int_to_string(x):
    """Convert integer x into a string of bytes, as per X9.62."""
    assert x >= 0
    if x == 0:
        return b'\0'
    result = []
    while x:
        ordinal = x & 0xFF
        result.append(bytes((ordinal,)))
        x >>= 8
    result.reverse()
    return b''.join(result)


def string_to_int(s):
    """Convert a string of bytes into an integer, as per X9.62."""
    result = 0
    for c in s:
        if not isinstance(c, int):
            c = ord(c)
        result = 256 * result + c
    return result


def string_to_array(x):
    a = []
    for i in range(len(x)):
        a.append(ord(x[i]))
    return a


def integer_to_array(i, size):
    a = []
    for b in range(size):
        a.append(((i % 256) + 256) % 256)
        i = i // 256
    a.reverse()
    return a


def serialize_list(l):
    m = []
    for i in l:
        m += serialize(i)
    return m


def serialize(data):
    # if data is Number
    if type(data) in (int, float):
        return integer_to_array(3, 1) + integer_to_array(data, 64)
    # if data is List
    elif type(data) in (list, tuple):
        if data[0] == -6:
            d0 = data[1:]
            rest = serialize_list(d0)
            return integer_to_array(1, 1) + integer_to_array(len(rest), 4) + rest
        elif data[0] == -7:
            d0 = data[1:]
            rest = serialize_list(d0)
            return integer_to_array(2, 1) + integer_to_array(len(rest), 4) + rest
        elif type(data[0]) == str:
            h = data[0]
            d0 = data[1:]
            atom_size = len(h)
            first = integer_to_array(4, 1) + integer_to_array(atom_size, 4) + string_to_array(h)
            rest = first + serialize_list(d0)

            return integer_to_array(2, 1) + integer_to_array(len(rest), 4) + rest

    if type(data) == str:
        rest = [x for x in b64decode(data)]
        return integer_to_array(0, 1) + integer_to_array(len(rest), 4) + rest
    else:
        return integer_to_array(0, 1) + integer_to_array(len(data), 4) + data


def sign_tx(tx_data, private_key):
    serialized_tx = serialize(tx_data)
    key = SigningKey.from_string(unhexlify(private_key), curve=SECP256k1, hashfunc=hashlib.sha256)
    sign = key.sign_deterministic(bytes(serialized_tx), sigencode=sigencode_der)
    sign_str = b64encode(sign).decode()

    return sign_str

def get_tx_hash(tx_data):
    serialized_tx = serialize(tx_data)

    txhash = hashlib.sha256(bytes(serialized_tx)).digest()

    return b64encode(txhash).decode()
