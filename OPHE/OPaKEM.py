from utils import *
from Crypto.Random import get_random_bytes
import time
import os
import base64



def opakem_keygen():
    sk = generate_sk()
    Str = {}
    return sk, Str



#Token
def opakem_token(sk,mid,pw,uid,sid):
    ## C
    r_0 = generate_sk()
    Hpw = H1(pw)
    a_0 = r_0 * Hpw
    ## S
    d1 = (sk + H2(str_to_bytes(uid + sid))) % order
    d2 = (sk + H2(str_to_bytes(uid + sid + mid))) % order
    a_1 = inv(d1) * a_0  # S1
    a_1m = inv(d2) * a_0  # S1m

    # a_1 = inv((sk + H2(str_to_bytes(uid+sid))) % order) * a_0
    # a_1m = inv((sk + H2(str_to_bytes(uid+sid+mid))) % order) * a_0
    ## C
    a_2 = inv(r_0) * a_1
    a_2m = inv(r_0) * a_1m
    y = H3(uid+sid, pw, a_2)
    y_mid=H3(uid+sid, pw, a_2m)
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

    uid = "user_ophe"
    sid = "server_ophe"
    # pw = "passw0rd"
    pw_bytes = os.urandom(256)
    pw = base64.urlsafe_b64encode(pw_bytes).decode('utf-8')
    mid ="session_id_01"

    run_time = {
        # "keygen_time":0,
        "token_time":0,
        "opakem_enc_time":0,
        "opakem_dec_time":0
    }
    time_set = {}

    for i in range(10):
        print(f"\n=========== 第 {i + 1} 次测试 ===========")
        start_time1 = time.time()
        sk, Str = opakem_keygen()
        end_time1 = time.time()
        keygen_time = (end_time1 - start_time1)*1000
        # time_set["keygen_time"] = keygen_time

        # Token Generation
        start_time2 = time.time()
        y,y_m, a_0, a_1,a_1m = opakem_token(sk, mid, pw, uid, sid)
        end_time2 = time.time()
        token_time = (end_time2 - start_time2)*1000
        print("token_time = ", token_time)
        time_set["token_time"] = token_time

        # Encapsulation
        start_time3 = time.time()
        ek, k = opakem_encapsulation(y)
        end_time3 = time.time()
        opakem_enc_time = (end_time3 - start_time3)*1000
        print("opakem_enc_time = ", opakem_enc_time)
        time_set["opakem_enc_time"] = opakem_enc_time
        print("k:", point_to_str(k))

        # Decapsulation
        start_time4 = time.time()
        k_prime = opakem_decapsulation(y, ek)
        end_time4 = time.time()
        opakem_dec_time = (end_time4 - start_time4)*1000
        print("opakem_dec_time = ", opakem_dec_time)
        time_set["opakem_dec_time"] = opakem_dec_time

        for key in run_time:
            if key in time_set:
                run_time[key] += time_set[key]
            else:
                print(f"⚠️ Warning: 第{i + 1}次测试未记录指标 {key}")

        print("k_prime:", point_to_str(k_prime))
        if k == k_prime:
            print("Decapsulation successful, keys match.")
    print("\n======== 📊 平均耗时统计（单位：ms）========")
    for key in run_time:
        avg_time = run_time[key] / 10
        print(f"{key}: {avg_time:.2f} ms")




