import random
from utils import *
from Crypto.Random import get_random_bytes
import time



# msk generation


# sk generation

def key_gen(msk):
    r = generate_sk()
    e = r * generator  # g_to_r
    sk = H2(point_to_bytes(msk * e))
    return sk,e

def key_rotation(e,msk):
    msk_prime = generate_sk()
    delta = msk * inv(msk_prime)
    e_prime = delta * e
    sk_prime = H2(point_to_bytes(msk_prime * e_prime))
    return sk_prime

if __name__ == "__main__":
    id = "id"
    pw = "passw0rd"
    msk = generate_sk()
    sk,e = key_gen(msk)
    print("sk:", sk)
    sk_prime = key_rotation(e,msk)
    print("sk_prime:", sk_prime)

