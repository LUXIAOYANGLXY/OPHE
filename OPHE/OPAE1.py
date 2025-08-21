from utils import *
from Crypto.Random import get_random_bytes
import time
from NIZK import *
from OPaKEM import *
import timeit

# Key Generation
##S
def opae_initialization():
    sk = generate_sk()
    Str = {}
    return sk,Str

def opae_encryption(sk, Str, id, pw, mid, g, m,iv):
    ##S
    #Encryption----------------------------------------------------------------------------
    ###C和S运行opakem_token
    y,y_m, a0, a1,a1_m= opakem_token(sk,mid,pw,id)
    v = H2(str_to_bytes(id+mid))
    w = (sk + v) % order
    gw = generate_pk(w)
    #S运行NIZK.prove
    # nizk_prove(sk, id, mid, g, gw, a1, a0)
    pi = nizk_prove(sk, id, mid, g, gw, a1, a0)
    #C运行NIZK.verify
    pk_gv = pk + v * g
    valid = nizk_verify(id, mid, g, pk_gv, a1, a0, pi)
    print("NIZK verification result:", valid)

    #C运行opakem_encapsulation
    ek,k=opakem_encapsulation(y)
    #C运行aes_gcm_encrypt

    c, tag = aes_gcm_encrypt(point_to_256bits(k), str_to_bytes(m), iv)

    #S存储id，mid和ek,c
    Str[(id, mid)] = {
        "id": id,
        "mid": mid,
        'ek': ek
    }
    print("Str:", Str)
    # print("Str[id]:",Str['t'])
    print("Str[(id, mid)]:", Str[(id, mid)]['ek'])
    return ek,c,tag
    #Encryption----------------------------------------------------------------------------


def opae_decryption(ek, c, tag, iv, sk, id_prime, pw_prime, mid_prime):
    #Decryption----------------------------------------------------------------------------
    #C和S运行opakem_token
    y_prime,y_prime_mid, a0_prime, a1_prime,a1_prime_mid = opakem_token(sk, mid_prime,pw_prime, id_prime)
    #C运行opakem.decapsulation
    k_prime=opakem_decapsulation(y_prime, ek)
    #C运行aes_gcm_decrypt
    m_prime = bytes_to_str(aes_gcm_decrypt(point_to_256bits(k_prime), c, tag, iv))
    print("m_prime:", m_prime)
    # print("OPAE解密成功")
    # print("Decryption result:", m_prime)
    #Decryption----------------------------------------------------------------------------

if __name__ == "__main__":
    #初始化
    ###C
    id = "user001"
    pw = "passw0rd"
    mid = "sessionA"
    g = generator
    m= "Hello, this is a test message."
    # source_file_path = "./1mb"
    # # source_file_path = "./10mb"
    # # source_file_path = "./100mb"
    # # source_file_path = "./300mb"
    #
    # with open(source_file_path, 'r', encoding='utf-8') as f_in:
    #     m = f_in.read().strip()
    #opae的初始化阶段
    sk,Str=opae_initialization()
    pk = generate_pk(sk)
    #opae的加密阶段
    iv = get_random_bytes(12)
    ek,c,tag=opae_encryption(sk, Str, id, pw, mid, g, m, iv)
    #opae的解密阶段
    id_prime = "user001"
    pw_prime = "passw0rd"
    mid_prime = "sessionA"
    opae_decryption(ek, c, tag, iv, sk,id_prime, pw_prime, mid_prime)









