from Crypto.Random import get_random_bytes

from utils import *
import hashlib

def nizk_prove(sk: int, uid: str, mid: str, g, gw, a1, a0,sid) -> tuple[int, int]:
    r = generate_sk()
    g1 = a1

    s1 = r * g
    s2 = r * g1

    id_mid_bytes = str_to_bytes(uid+sid+ mid)
    v = H2(id_mid_bytes)
    w = (sk + v) % order

    # print("g:", point_to_str(g))
    # print("gw:", point_to_str(gw))
    # print("a1:", point_to_str(a1))
    # print("a0:", point_to_str(a0))
    # print("s1:", point_to_str(s1))
    # print("s2:", point_to_str(s2))
    beta = H4(g, gw, a1, a0, s1, s2)
    # print("gw:", point_to_str(gw))
    # print("a1:", point_to_str(a1))
    # print("a0:", point_to_str(a0))
    # print("s1:", point_to_str(s1))
    # print("s2:", point_to_str(s2))

    # print("beta:",beta)
    # print("-----------------------------------------------------------------------------------------------------------------")

    z = (r - beta * w) % order
    #  π = (z, β)
    return z, beta


def nizk_verify(uid: str, mid: str, g, pk_gv, a1, a0, pi: tuple[int, int],sid) -> bool:
    z, beta = pi

    id_mid_bytes = str_to_bytes(uid+sid+mid)
    v = H2(id_mid_bytes)

    g_v = v * g

    s1_prime = z * g + beta * pk_gv

    s2_prime = z * a1 + beta * a0
    #
    # print("g:", point_to_str(g))
    # print("pk+g_v:", point_to_str(pk_gv))
    # print("a1:", point_to_str(a1))
    # print("a0:", point_to_str(a0))
    # print("s1:", point_to_str(s1_prime))
    # print("s2:", point_to_str(s2_prime))
    beta_prime = H4(g, pk_gv, a1, a0, s1_prime, s2_prime)
    # print("pk_gv:", point_to_str(pk_gv))
    # print("a1:", point_to_str(a1))
    # print("a0:", point_to_str(a0))
    # print("s1_prime:", point_to_str(s1_prime))
    # print("s2_prime:", point_to_str(s2_prime))
    print("beta:", beta)
    print("beta_prime:", beta_prime)

    #  compare β == β'
    return beta == beta_prime


if __name__ == "__main__":
    # 生成密钥
    sk = generate_sk()
    pk = generate_pk(sk)

    # 用户身份
    uid = "user001"
    mid = "sessionA"
    sid = "server111"
    # mid = get_random_bytes(32)

    # 生成随机参数
    g = generator
    v = H2(str_to_bytes(uid+sid+mid) )
    w = (sk + v) % order
    gw = generate_pk(w)

    a0 = random_generator()
    a1 = inv((sk + v) % order) * a0

    # 生成 NIZK 证明
    pi = nizk_prove(sk, uid, mid, g, gw, a1, a0,sid)

    # 验证 NIZK
    pk_gv = pk + v * g
    # pk_gv = pk * v
    valid = nizk_verify(uid, mid, g, pk_gv, a1, a0, pi,sid)
    print("NIZK verification result:", valid)  # True
