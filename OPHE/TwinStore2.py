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

def twinstore_register(sk, id, pw, Reg):
    opa_register11(sk, id, pw, Reg)
    # return y


def twinstore_encrypt(sk,g,id_prime, mid_prime,pw_prime, m, Reg,Str,iv):
    # This function would handle the encryption logic
    ###C和S运行OPA认证
    a_0,a_1,a_1m,b,y_prime,y_prime_mid=opa_authenticate11(sk, id_prime,mid_prime, pw_prime, Reg)#############
    v = H2(str_to_bytes(id_prime+ mid_prime))
    w = (sk + v) % order
    gw = generate_pk(w)
    pk = generate_pk(sk)
    # S运行NIZK.prove
    pi = nizk_prove(sk, id_prime, mid_prime, g, gw, a_1, a_0)  ##########
    # C运行NIZK.verify
    pk_gv = pk + v * g
    valid = nizk_verify(id_prime, mid_prime, g, pk_gv, a_1, a_0, pi)############
    ek,k=opakem_encapsulation(y_prime_mid) #######

    #############################################灰色字迹###################################
    # C
    r1 = generate_sk()
    b0 = k + g * r1
    # S
    b1 = b0 * sk
    # C
    # b2 = b1 + g * (-sk * r1 % order)
    b2 = b1 + pk * (-r1 % order)
    # print("id:", id)
    # print("mid:", mid)
    # print("point_to_str(ek):", point_to_str(ek))
    # print("b2:", point_to_str(b2) )
    # print("sk*k:",point_to_str(k * sk))
    # print("k:", point_to_str(k))
    # print("y:", y)
    t = H3(id + mid, point_to_str(ek), b2)
    print("b2:", point_to_str(b2))
    print("ENC_t:", t)

    print("ek:", point_to_str(ek))
    print("k:", point_to_str(k))
    print("y_prime_mid:", y_prime_mid)
    Str[id_prime]= {
        'id': id_prime,
        'mid': mid,
        'ek': ek,
        't': t
    }

    c, tag = aes_gcm_encrypt(point_to_256bits(k), str_to_bytes(m), iv)
    print("c:", c)
    return c,tag,Str


def twinstore_decrypt(c,tag,iv,sk,id_prime, mid_prime, pw_prime,Str):
    # C和S运行opakem_token
    if id_prime not in Str[id_prime] or  mid_prime not in Str[id_prime]:
        print("用户未注册，请检查")
        return None
    y_prime,y_prime_mid, a0_prime, a1_prime,a1_prime_mid = opakem_token(sk, mid_prime, pw_prime, id_prime)
    print("y_prime_mid:", y_prime_mid)
    r1_prime = generate_sk()
    b0_prime = r1_prime
    # C运行opakem.decapsulation
    k_prime = opakem_decapsulation(y_prime_mid, Str[id_prime]['ek'])
    print("k_prime:", point_to_str(k_prime))
    # C运行aes_gcm_decrypt
    m_prime = bytes_to_str(aes_gcm_decrypt(point_to_256bits(k_prime), c, tag, iv))
    print("m_prime:", m_prime)
    b1_prime = b0_prime * bytes_to_int(y_prime_mid)

    # S
    b2_prime = b1_prime * inv(r1_prime)
    k_prime_prime = Str[id_prime]['ek'] * inv(b2_prime)
    # print("id_prime:", id_prime)
    # print("mid_prime:", mid_prime)
    # print("point_to_str(ek):", point_to_str(ek))
    print("k_prime_prime * sk:", point_to_str(k_prime_prime * sk))
    # print("sk*k_prime:", point_to_str(sk * k_prime))
    # print("k_prime:", point_to_str(k_prime))
    # print("k_prime_prime:", point_to_str(k_prime_prime))
    # print("y_prime:", y_prime)
    print("ek:", point_to_str(Str[id_prime]['ek']))
    t_prime = H3(id_prime + mid_prime, point_to_str(Str[id_prime]['ek']), k_prime_prime * sk)
    if Str[id_prime]['t'] == t_prime:
        print("OPAE解密成功")
    else:
        print("OPAE解密失败，t不匹配")

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
    id = "id"
    pw = "passw0rd"
    mid = "mid"
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
    twinstore_register(sk, id, pw, Reg)
    print("Reg:", Reg)

    #C和S运行authenticate,加密
    id_prime = "id"
    mid_prime = "mid"
    pw_prime = "passw0rd"
    print("m:", m)
    c,tag,Str=twinstore_encrypt(sk, g,id_prime, mid_prime, pw_prime, m, Reg,Str,iv)
    print("Reg:", Reg)

    #C和S运行解密
    id_prime = "id"
    mid_prime = "mid"
    pw_prime = "passw0rd"
    print("Str:", Str)
    print("Str[id]:",Str[id])

    twinstore_decrypt(c,tag,iv,sk,id_prime, mid_prime, pw_prime,Str)












