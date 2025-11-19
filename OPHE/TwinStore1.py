from utils import *
from Crypto.Random import get_random_bytes
import time
from OPaKEM import *
from OPA11 import *
from Rotation import *
from NIZK import nizk_prove, nizk_verify



def twinstore_setup():
    # global sk, Str
    sk,Str = opakem_keygen()
    Reg = {}
    return sk, Str,Reg

def twinstore_register(sk, uid, pw, Reg,sid):
    opa_register11(sk, uid, pw, Reg, sid)
    # return y


def twinstore_encrypt(sk,g,uid_prime, mid_prime,pw_prime, m, Reg,Str,iv,sid_prime):
    # This function would handle the encryption logic
    ###C和S运行OPA认证
    a_0,a_1,a_1m,b,y_prime,y_prime_mid=opa_authenticate11(sk, uid_prime,mid_prime, pw_prime, Reg,sid_prime)#############

    ##S
    v = H2(str_to_bytes(uid_prime +sid_prime+ mid_prime))
    w = (sk + v) % order
    gw = generate_pk(w)
    pk = generate_pk(sk)
    # S运行NIZK.prove
    pi = nizk_prove(sk, uid_prime, mid_prime, g, gw, a_1m, a_0,sid_prime)  ##########
    # C运行NIZK.verify
    pk_gv = pk + v * g
    valid = nizk_verify(uid_prime, mid_prime, g, pk_gv, a_1m, a_0, pi,sid_prime)############
    ek,k=opakem_encapsulation(y_prime_mid) #######
    print("ek:", point_to_str(ek))
    print("k:", point_to_str(k))
    print("y_prime_mid:", y_prime_mid)
    Str[uid_prime]= {
        'uid': uid_prime,
        'mid': mid,
        'ek': ek,
    }

    c, tag = aes_gcm_encrypt(point_to_256bits(k), str_to_bytes(m), iv)
    print("c:", c)
    return c,tag,Str



def twinstore_decrypt(c,tag,iv,sk,uid_prime, mid_prime, pw_prime,Str,sid_prime):
    # C和S运行opakem_token
    print("uid_prime:", uid_prime)
    print("mid_prime:", mid_prime)
    # if uid_prime not in Str[uid_prime] or  mid_prime not in Str[uid_prime]:
    if Str[uid_prime]['uid'] != uid_prime or Str[uid_prime]['mid'] != mid_prime:
        print("用户未注册，请检查")
        return None
    y_prime,y_prime_mid, a0_prime, a1_prime,a1_prime_mid = opakem_token(sk, mid_prime, pw_prime, uid_prime,sid_prime)
    print("y_prime_mid:", y_prime_mid)
    # C运行opakem.decapsulation
    k_prime = opakem_decapsulation(y_prime_mid, Str[uid_prime]['ek'])
    print("k_prime:", point_to_str(k_prime))
    # C运行aes_gcm_decrypt
    m_prime = bytes_to_str(aes_gcm_decrypt(point_to_256bits(k_prime), c, tag, iv))
    print("m_prime:", m_prime)

    # print("OPAE解密成功")



def twinstore_rotation(msk):
    # This function would handle the key rotation logic
    sk,e=key_gen(msk)
    sk_prime = key_rotation(e,msk)
    return sk_prime



if __name__ == "__main__":
    #S
    sk,Str,Reg = twinstore_setup()
    print("Reg", Reg)
    pk = generate_pk(sk)
    g = generator
    #Register
    #C
    uid = "id"
    pw = "passw0rd"
    mid = "mid"
    sid = "server"
    m = "message"
    iv = get_random_bytes(12)

    # # # #added file*********************************************************************************
    # source_file_path = "./1mb"
    # # source_file_path = "./10mb"
    # # source_file_path = "./100mb"
    # # source_file_path = "./300mb"
    #
    # with open(source_file_path, 'r', encoding='utf-8') as f_in:
    #     m = f_in.read().strip()
    # # #*********************************************************************************

    ###C和S运行register
    twinstore_register(sk, uid, pw, Reg,sid)
    print("Reg:", Reg)

    #C和S运行authenticate,加密
    uid_prime = "id"
    mid_prime = "mid"
    sid_prime = "server"
    pw_prime = "passw0rd"
    print("m:", m)
    c,tag,Str=twinstore_encrypt(sk, g,uid_prime, mid_prime, pw_prime, m, Reg,Str,iv,sid_prime)
    print("Reg:", Reg)

    #C和S运行解密
    uid_prime = "id"
    mid_prime = "mid"
    sid_prime = "server"
    pw_prime = "passw0rd"
    print("Str:", Str)
    print("Str[uid]:",Str[uid])


    twinstore_decrypt(c,tag,iv,sk,uid_prime, mid_prime, pw_prime,Str,sid_prime)












