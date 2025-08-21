import os

from utils import *
from Crypto.Random import get_random_bytes
import time



def opakem_keygen():
    sk = generate_sk()
    Str = {}
    return sk, Str



#Token
def opakem_token(sk,mid,pw,id):
    ## C
    r_0 = generate_sk()
    a_0 = r_0 * H1(pw)
    ## S
    a_1 = inv((sk + H2(str_to_bytes(id))) % order) * a_0
    a_1m = inv((sk + H2(str_to_bytes(id +mid))) % order) * a_0
    ## C
    a_2 = inv(r_0) * a_1
    a_2m = inv(r_0) * a_1m
    y = H3(id, pw, a_2)
    y_mid=H3(id, pw, a_2m)
    ##S NIZK prove
    ##C NIZK verify
    return y,y_mid,a_0,a_1,a_1m

# Encapsulation
def opakem_encapsulation(y):
    k = random_generator()
    ek = bytes_to_int(y) * k
    return ek,k

# Decapsulation
def opakem_decapsulation(y_prime,ek):
    k_prime = inv(bytes_to_int(y_prime)) * ek
    return k_prime

if __name__ == '__main__':

    id = "id"
    # pw = "passw0rd"
    pw_bytes = os.urandom(12)  # Generate a random password
    #pw转成字符串
    pw = bytes_to_str(pw_bytes)
    mid ="session_id"


    sk, Str = opakem_keygen()
    # Token Generation
    y,y_m, a_0, a_1,a_1m = opakem_token(sk, mid, pw, id)
    # Encapsulation
    ek, k = opakem_encapsulation(y)
    print("k:", point_to_str(k))
    # Decapsulation
    k_prime = opakem_decapsulation(y, ek)
    print("k_prime:", point_to_str(k_prime))
    if k == k_prime:
        print("Decapsulation successful, keys match.")




