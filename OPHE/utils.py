import pickle
import struct

import ecdsa
from ecdsa import SECP256k1, ellipticcurve
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

order = SECP256k1.order
generator = SECP256k1.generator


def generate_sk() -> int:
    return ecdsa.util.randrange(order)


def generate_pk(sk) -> ellipticcurve.PointJacobi:
    return sk * generator


def random_generator() -> ellipticcurve.PointJacobi:
    return ecdsa.util.randrange(order) * generator


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder="big")


def bytes_to_int(x: bytes) -> int:
    return int.from_bytes(x, byteorder="big")


def str_to_bytes(x: str) -> bytes:
    return x.encode("utf-8")


def bytes_to_str(x: bytes) -> str:
    return x.decode("utf-8", errors="replace")


def point_to_str(point: ellipticcurve.PointJacobi):
    point = point.to_affine()
    return "(x: {}, y: {})".format(point.x(), point.y())


def inv(k):
    return pow(k, -1, order)


def H1(msg: str) -> ellipticcurve.PointJacobi:
    sha256_hash = hashlib.sha256(str_to_bytes(msg)).digest()
    hash_int = bytes_to_int(sha256_hash)
    sk = hash_int % order
    return generate_pk(sk)


def H2(msg: bytes) -> int:
    sha256_hash = hashlib.sha256(msg).digest()
    hash_int = bytes_to_int(sha256_hash)
    return hash_int


def H3(msg1: str, msg2: str, msg3: ellipticcurve.PointJacobi) -> bytes:
    sha256_hash = hashlib.sha256()
    sha256_hash.update(str_to_bytes(msg1))

    sha256_hash.update(str_to_bytes(msg2))

    point = msg3.to_affine()
    point_bytes = int_to_bytes(point.x()) + int_to_bytes(point.y())
    sha256_hash.update(point_bytes)

    return sha256_hash.digest()

def H4(*args) -> int:
    """Hash multiple elliptic curve points into an integer (mod q)."""
    sha = hashlib.sha256()
    for arg in args:
        if isinstance(arg, ellipticcurve.PointJacobi):
            arg = arg.to_affine()
            sha.update(int_to_bytes(arg.x()))
            sha.update(int_to_bytes(arg.y()))
        else:
            raise TypeError("H4 expects elliptic curve points")
    return bytes_to_int(sha.digest()) % order


def point_to_bytes(point: ellipticcurve.PointJacobi) -> bytes:
    point = point.to_affine()
    return int_to_bytes(point.x()) + int_to_bytes(point.y())


def point_to_256bits(point: ellipticcurve.PointJacobi) -> bytes:
    point = point.to_affine()
    point_bytes = int_to_bytes(point.x()) + int_to_bytes(point.y())
    return hashlib.sha256(point_bytes).digest()


def aes_gcm_encrypt(key: bytes, msg: bytes, iv):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    padded_data = pad(msg, AES.block_size)
    return cipher.encrypt_and_digest(padded_data)


def aes_gcm_decrypt(key: bytes, ctx: bytes, tag, iv) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        padded_data = cipher.decrypt_and_verify(ctx, tag)
        data = unpad(padded_data, AES.block_size)
        return data
    except ValueError:
        return b""

def recv_with_length(sock):
    # 先接收前4个字节，表示后续数据长度
    raw_msglen = sock.recv(4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    data = b''
    while len(data) < msglen:
        packet = sock.recv(msglen - len(data))
        if not packet:
            return None
        data += packet
    return pickle.loads(data),4+msglen
    # return pickle.loads(data)

def send_with_length(sock, obj):
    data = pickle.dumps(obj)
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length)  # 先发送数据长度
    sock.sendall(data)  # 再发送数据本体
    return 4 + len(data)

def recv_with_length0(sock):
    # 先接收前4个字节，表示后续数据长度
    raw_msglen = sock.recv(4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    data = b''
    while len(data) < msglen:
        packet = sock.recv(msglen - len(data))
        if not packet:
            return None
        data += packet
    # return pickle.loads(data),4+msglen
    return pickle.loads(data)

def send_with_length0(sock, obj):
    data = pickle.dumps(obj)
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length)  # 先发送数据长度
    sock.sendall(data)  # 再发送数据本体
    # return 4 + len(data)