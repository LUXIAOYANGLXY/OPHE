import random
from utils import *
import time


# Key Generation
def opa_keygen2():
    sk = generate_sk()
    Reg = {}
    return sk, Reg


# Registration
def opa_register2(sk, id, pw, Reg):
    ## C
    r_0 = generate_sk()
    a_0 = r_0 * H1(pw)
    ## S
    a_1 = inv((sk + H2(str_to_bytes(id))) % order) * a_0
    ## C
    a_2 = inv(r_0) * a_1
    y = H3(id, pw, a_2)
    x = H2(y) * generator
    ## S
    Reg[id] = {
        'id':id,
        'cy':x
    }
    return x

# Authentication
def opa_authenticate2(sk, id_prime, pw_prime, Reg):
    ## C
    r_0_prime = generate_sk()
    a_0_prime = r_0_prime * H1(pw_prime)
    t = generate_sk()
    b = t * generator
    ## S
    if id_prime in Reg:
        a_1_prime = inv((sk + H2(str_to_bytes(id_prime))) % order) * a_0_prime
        c_m = generate_sk()
        print("用户已注册")
    else:
        print("用户未注册，请检查")
    ## C
    a_2_prime = inv(r_0_prime) * a_1_prime
    y_prime = H3(id_prime, pw_prime, a_2_prime)
    r_c = t + c_m * H2(y_prime)
    ## S
    left = r_c * generator
    right = b + c_m * x
    print(" left = " + point_to_str(left))
    print("right = " + point_to_str(right))
    print("Authentication " + "Passed" if left == right else "Failed")

if __name__ == "__main__":
    id = "id"
    pw = "passw0rd"

    sk, Reg = opa_keygen2()

    x = opa_register2(sk, id, pw, Reg)

    id_prime = "id"
    pw_prime = "passw0rd"
    opa_authenticate2(sk, id_prime, pw_prime, Reg)
