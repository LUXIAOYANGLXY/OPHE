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

def opae_encryption_2(sk, Str, uid, pw, mid, g, m,iv,sid):
    ##S
    #Encryption----------------------------------------------------------------------------
    ###C和S运行opakem_token
    y,y_m, a0, a1,a1_m= opakem_token(sk,mid,pw,uid,sid)
    v = H2(str_to_bytes(uid+sid+mid))
    w = (sk + v) % order
    gw = generate_pk(w)
    #S运行NIZK.prove
    # nizk_prove(sk, uid, mid, g, gw, a1, a0)
    pi = nizk_prove(sk, uid, mid, g, gw, a1_m, a0,sid)
    #C运行NIZK.verify
    pk_gv = pk + v * g
    valid = nizk_verify(uid, mid, g, pk_gv, a1_m, a0, pi,sid)
    print("NIZK verification result:", valid)

    #C运行opakem_encapsulation
    ek,k=opakem_encapsulation(y)

    #############################################灰色字迹###################################
    #C
    r1 = generate_sk()
    b0 = k+g*r1
    #S
    b1=b0 * sk
    #C
    b2=b1 + g * (-sk * r1 % order)
    # print("uid:", id)
    # print("mid:", mid)
    # print("point_to_str(ek):", point_to_str(ek))
    # print("b2:", point_to_str(b2) )
    # print("sk*k:",point_to_str(k * sk))
    # print("k:", point_to_str(k))
    # print("y:", y)
    t = H3(uid+sid+mid ,point_to_str(ek), b2)



    #C运行aes_gcm_encrypt
    c, tag = aes_gcm_encrypt(point_to_256bits(k), str_to_bytes(m), iv)

    #S存储uid，mid和ek,c
    # Str[uid, mid,t] = ek
    # S存储uid，mid和ek,c
    Str[(uid, mid)] = {
        'uid': uid,
        'mid': mid,
        'ek': ek,
        't': t
    }
    return ek,c,tag,Str
    #Encryption----------------------------------------------------------------------------


def opae_decryption_2(ek, c, tag, iv, sk, Str, g,uid_prime, pw_prime, mid_prime,sid_prime):
    #Decryption----------------------------------------------------------------------------
    #C和S运行opakem_token
    y_prime,y_prime_mid, a0_prime, a1_prime,a1_prime_mid = opakem_token(sk, mid_prime,pw_prime, uid_prime,sid_prime)
    #S
    r1_prime = generate_sk()
    b0_prime = r1_prime

    #C运行opakem.decapsulation
    k_prime=opakem_decapsulation(y_prime, ek)
    #C运行aes_gcm_decrypt
    m_prime = bytes_to_str(aes_gcm_decrypt(point_to_256bits(k_prime), c, tag, iv))
    b1_prime = b0_prime * bytes_to_int(y_prime)

    # S
    b2_prime = b1_prime * inv(r1_prime)
    k_prime_prime = ek * inv(b2_prime)
    # k_prime_prime = ek * inv(r1_prime)
    # print("uid_prime:", uid_prime)
    # print("mid_prime:", mid_prime)
    # print("point_to_str(ek):", point_to_str(ek))
    print("k_prime_prime * sk:",point_to_str(k_prime_prime * sk))
    print("sk*k_prime:", point_to_str(sk * k_prime))
    # print("k_prime:", point_to_str(k_prime))
    # print("k_prime_prime:", point_to_str(k_prime_prime))
    # print("y_prime:", y_prime)
    # print("ek:", point_to_str(ek))
    t_prime = H3(uid_prime+sid_prime + mid_prime, point_to_str(ek), k_prime_prime * sk)
    if Str[(uid, mid)]['t'] == t_prime:
        print("OPAE解密成功")
    else:
        print("OPAE解密失败，t不匹配")
    # print("OPAE解密成功")
    # print("Decryption result:", m_prime)
    #Decryption----------------------------------------------------------------------------



if __name__ == "__main__":
    #初始化
    ###C
    uid = "user001"
    pw = "passw0rd"
    mid = "sessionA"
    sid = "server111"
    g = generator
    # m= "Hello, this is a test message."
    source_file_path = "./1mb"
    # source_file_path = "./10mb"
    # source_file_path = "./100mb"
    # source_file_path = "./300mb"

    with open(source_file_path, 'r', encoding='utf-8') as f_in:
        m = f_in.read().strip()
    #opae的初始化阶段
    sk,Str=opae_initialization()
    pk = generate_pk(sk)
    #opae的加密阶段
    iv = get_random_bytes(12)
    ek,c,tag,Str=opae_encryption_2(sk, Str, uid, pw, mid, g, m, iv,sid)
    #opae的解密阶段
    uid_prime = "user001"
    pw_prime = "passw0rd"
    mid_prime = "sessionA"
    sid_prime = "server111"
    opae_decryption_2(ek, c, tag, iv, sk,Str,g,uid_prime, pw_prime, mid_prime,sid_prime)









