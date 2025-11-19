import pickle
import struct
import hashlib
from ecdsa import SECP256k1, NIST384p, NIST521p, ellipticcurve
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import ecdsa

# ==============================
# 安全参数设置
# 可选：256, 384, 521
SECURITY_LEVEL = 521
# ==============================

# 选择曲线
if SECURITY_LEVEL == 256:
    curve = SECP256k1
    AES_KEY_BYTES = 32  # AES-256
    ECC_NAME = "SECP256k1"
    SECURITY_BITS = 128
elif SECURITY_LEVEL == 384:
    curve = NIST384p
    AES_KEY_BYTES = 24  # AES-192
    ECC_NAME = "NIST384p"
    SECURITY_BITS = 192
elif SECURITY_LEVEL == 521:
    curve = NIST521p
    AES_KEY_BYTES = 32  # AES-256
    ECC_NAME = "NIST521p"
    SECURITY_BITS = 256
else:
    raise ValueError("Unsupported SECURITY_LEVEL, choose 256, 384, or 521")

order = curve.order
generator = curve.generator

def print_security_info():
    print("=== 当前安全参数 ===")
    print(f"ECC 曲线: {ECC_NAME}")
    print(f"曲线位数: {curve.baselen * 8} 位")
    print(f"AES 密钥长度: {AES_KEY_BYTES * 8} 位")
    print(f"等效安全强度: ~ AES-{SECURITY_BITS}")
    print("=" * 26)

# 程序启动时打印一次
print_security_info()

# ------------------ ECC & AES 工具函数 ------------------
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
    sha = hashlib.sha512(str_to_bytes(msg)).digest()
    hash_int = bytes_to_int(sha)
    sk = hash_int % order
    return generate_pk(sk)

def H2(msg: bytes) -> int:
    sha = hashlib.sha512(msg).digest()
    return bytes_to_int(sha)

def H3(msg1: str, msg2: str, msg3: ellipticcurve.PointJacobi) -> bytes:
    sha = hashlib.sha512()
    sha.update(str_to_bytes(msg1))
    sha.update(str_to_bytes(msg2))
    point = msg3.to_affine()
    point_bytes = int_to_bytes(point.x()) + int_to_bytes(point.y())
    sha.update(point_bytes)
    return sha.digest()[:AES_KEY_BYTES]

def H4(*args) -> int:
    sha = hashlib.sha512()
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

def point_to_key(point: ellipticcurve.PointJacobi) -> bytes:
    """根据 SECURITY_LEVEL 生成对应 AES 密钥"""
    point = point.to_affine()
    point_bytes = int_to_bytes(point.x()) + int_to_bytes(point.y())
    return hashlib.sha512(point_bytes).digest()[:AES_KEY_BYTES]

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
    return pickle.loads(data), 4 + msglen

def send_with_length(sock, obj):
    data = pickle.dumps(obj)
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length)
    sock.sendall(data)
    return 4 + len(data)

def recv_with_length0(sock):
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
    return pickle.loads(data)

def send_with_length0(sock, obj):
    data = pickle.dumps(obj)
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length)
    sock.sendall(data)
