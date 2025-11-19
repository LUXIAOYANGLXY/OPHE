import random
from utils import *
import time


# Key Generation
def opa_keygen2():
    sk = generate_sk()
    Reg = {}
    return sk, Reg


# Registration
def opa_register2(sk, uid, pw, Reg,sid):
    ## C
    r_0 = generate_sk()
    a_0 = r_0 * H1(pw)
    ## S
    a_1 = inv((sk + H2(str_to_bytes(uid+sid))) % order) * a_0
    ## C
    a_2 = inv(r_0) * a_1
    y = H3(uid+sid, pw, a_2)
    x = H2(y) * generator
    ## S
    Reg[uid] = {
        'uid':uid,
        'cy':x
    }
    return x

# Authentication
def opa_authenticate2(sk, uid_prime, pw_prime, Reg,sid_prime):
    ## C
    r_0_prime = generate_sk()
    a_0_prime = r_0_prime * H1(pw_prime)
    t = generate_sk()
    b = t * generator
    ## S
    if uid_prime in Reg:
        a_1_prime = inv((sk + H2(str_to_bytes(uid_prime+sid_prime))) % order) * a_0_prime
        c_m = generate_sk()
        print("用户已注册")
    else:
        print("用户未注册，请检查")
    ## C
    a_2_prime = inv(r_0_prime) * a_1_prime
    y_prime = H3(uid_prime+sid_prime , pw_prime, a_2_prime)
    r_c = t + c_m * H2(y_prime)
    ## S
    left = r_c * generator
    right = b + c_m * x
    print(" left = " + point_to_str(left))
    print("right = " + point_to_str(right))
    print("Authentication " + "Passed" if left == right else "Failed")

if __name__ == "__main__":
    uid = "id"
    pw = "passw0rd"
    sid = "server111"

    sk, Reg = opa_keygen2()

    x = opa_register2(sk, uid, pw, Reg,sid)

    uid_prime = "id"
    pw_prime = "passw0rd"
    sid_prime = "server111"
    opa_authenticate2(sk, uid_prime, pw_prime, Reg,sid_prime)
