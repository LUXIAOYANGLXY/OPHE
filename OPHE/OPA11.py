import random
from utils import *
from Crypto.Random import get_random_bytes
import time




def opa_keygen11():
    sk = generate_sk()
    Reg = {}
    return sk, Reg

# Registration
def opa_register11(sk, uid, pw,Reg,sid):
    ## C
    r_0 = generate_sk()
    a_0 = r_0 * H1(pw)
    ## S
    a_1 = inv((sk + H2(str_to_bytes(uid+sid))) % order) * a_0
    ## C
    a_2 = inv(r_0) * a_1
    y = H3(uid+sid, pw, a_2)
    cy = H2(y) * generator
    ## S
    Reg[uid] = {
        'uid': uid,
        'cy': cy
    }
    # return y  ##########################


def opa_authenticate11(sk, uid_prime,mid_prime, pw_prime, Reg,sid_prime):
    ## C
    r_0_prime = generate_sk()
    s = generate_sk()
    b =generate_pk(s)
    a_0_prime = r_0_prime * H1(pw_prime)
    # print("uid_prime =", uid_prime)
    ## S
    if uid_prime in Reg:
        a_1_prime = inv((sk + H2(str_to_bytes(uid_prime+sid_prime ))) % order) * a_0_prime
        a_1_prime_mid = inv((sk + H2(str_to_bytes(uid_prime +sid_prime+ mid_prime))) % order) * a_0_prime
        c_m = generate_sk()
    else:
        print("用户未注册，请检查")
    ## C
    a_2_prime = inv(r_0_prime) * a_1_prime
    a_2_prime_mid = inv(r_0_prime) * a_1_prime_mid
    y_prime = H3(uid_prime+sid_prime , pw_prime, a_2_prime)
    y_prime_mid = H3(uid_prime+sid_prime, pw_prime,a_2_prime_mid)
    # iv = get_random_bytes(12)
    # r_c, tag = aes_gcm_encrypt(y_prime, int_to_bytes(c_m), iv)
    r_c = s + c_m * H2(y_prime)
    ## S
    # c_m_prime = bytes_to_int(aes_gcm_decrypt(y, r_c, tag, iv))

    left = r_c * generator
    right = b + c_m * Reg[uid_prime]['cy']
    print(" left = " + point_to_str(left))
    print("right = " + point_to_str(right))
    print("Authentication " + "Passed" if left == right else "Failed")
    return a_0_prime,a_1_prime, a_1_prime_mid, b,y_prime ,y_prime_mid

#*********************************************************************************aut-test


if __name__ == "__main__":
    uid = "id"
    pw = "passw0rd"
    mid = "session_id"
    sid = "server111"
    sk, Reg = opa_keygen11()

    opa_register11(sk, uid, pw, Reg,sid)
    # print("Reg:",Reg)

    uid_prime = "id"
    pw_prime = "passw0rd"
    mid_prime = "session_id"
    sid_prime = "server111"

    a_0,a_1,a_1m,b,y_prime,y_prime_mid =opa_authenticate11(sk, uid_prime,mid_prime, pw_prime, Reg,sid_prime)



