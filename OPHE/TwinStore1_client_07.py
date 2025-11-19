import socket
import pickle
from Crypto.Random import get_random_bytes
from TwinStore1 import *
from utils import *
import time



g = generator



def client_run_register(uid, pw, run_time):
    HOST = '10.102.104.8'
    PORT = 25555

    # HOST = '127.0.0.1'
    # PORT = 20202

    # HOST = '54.250.191.84'
    # PORT = 20202
    communication_scale_register = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        try:
            s.connect((HOST, PORT))
        except Exception as e:
            print(f"[Client] Failed to connect to server: {e}")
            return

        print(f"enter socket.connect!")


        # C注册 opa_register11####################################################################################
        start_time1 = time.time()
        payload = {'type': '1'}
        com_bytes=send_with_length(s, payload)
        communication_scale_register += com_bytes

        r_0 = generate_sk()
        a_0 = r_0 * H1(pw)

        payload = {'uid': uid, 'a_0': a_0} #发送uid和a0

        com_bytes = send_with_length(s,payload)
        communication_scale_register += com_bytes
        print("[Client] Sent registration payload:", payload)

        payload,com_bytes =recv_with_length(s)
        a_1 = payload['a_1']
        sid = payload['sid']
        communication_scale_register += com_bytes

        a_2 = inv(r_0) * a_1
        y = H3(uid+sid, pw, a_2)
        cy = H2(y) * generator

        com_bytes = send_with_length(s,cy)
        communication_scale_register += com_bytes
        end_time1 = time.time()
        registration_time = (end_time1- start_time1)*1000
        print(f"[Client] Registration time: {registration_time}")
        run_time["register_time"] = registration_time

        run_time["communication_scale_register"] = communication_scale_register

        print("client注册完成")

        ########################################client注册完成######################################################

def client_run_enc(uid_prime, mid_prime, pw_prime,source_file_path, iv,run_time):
    #########数据加密和对秘钥的封装###################################################################################################
    HOST = '10.102.104.8'
    PORT = 25555

    # HOST = '127.0.0.1'
    # PORT = 20202

    # HOST = '54.250.191.84'
    # PORT = 20202

    communication_scale_enc = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        try:
            s.connect((HOST, PORT))
        except Exception as e:
            print(f"[Client] Failed to connect to server: {e}")
            return

        print(f"Enc enter socket.connect!")

        start_time1 = time.time()
        payload = {'type': '2'}
        com_bytes = send_with_length(s, payload)
        communication_scale_enc += com_bytes


        ###C与S运行opa_authenticate11
        r_0_prime = generate_sk()
        s0 = generate_sk()
        b = generate_pk(s0)
        a_0_prime = r_0_prime * H1(pw_prime)

        payload = {'uid_prime': uid_prime, 'mid_prime': mid_prime, 'a_0_prime': a_0_prime,'b': b}
        com_bytes =send_with_length(s, payload)
        communication_scale_enc += com_bytes

        payload,com_bytes = recv_with_length(s)
        communication_scale_enc += com_bytes
        # print("[Client] Sent registration payload:", payload)

        a_1_prime = payload['a_1_prime']
        a_1_prime_mid = payload['a_1_prime_mid']
        c_m = payload['c_m']
        sid = payload['sid']

        a_2_prime = inv(r_0_prime) * a_1_prime
        a_2_prime_mid = inv(r_0_prime) * a_1_prime_mid
        y_prime = H3(uid_prime+sid, pw_prime, a_2_prime)
        y_prime_mid = H3(uid_prime+sid, pw_prime, a_2_prime_mid)

        r_c = s0 + c_m * H2(y_prime)

        com_bytes =send_with_length(s, r_c)
        communication_scale_enc += com_bytes

        ack,com_bytes = recv_with_length(s)
        communication_scale_enc += com_bytes

        if ack == '0':
            print("认证失败")
            return
        elif ack == '1':
            print("认证通过")
        end_time1 = time.time()
        run_time["opa_authentication_time"] = (end_time1 - start_time1)*1000
        print("[Client] opa_authentication_time:", run_time["opa_authentication_time"])
        ####################################认证通过！！！################################################

        ####################################NIZK.verify###################################################
        start_time2 = time.time()
        payload,com_bytes = recv_with_length(s)
        communication_scale_enc += com_bytes

        pk = payload['pk']
        pi = payload['pi']
        v = H2(str_to_bytes(uid_prime +sid+ mid_prime))
        pk_gv = pk + v * g
        valid = nizk_verify(uid_prime, mid_prime, g, pk_gv, a_1_prime_mid, a_0_prime, pi,sid)  ############
        if valid:
            print("NIZK verification passed")
        else:
            print("NIZK verification failed")
            return
        end_time2 = time.time()
        run_time["NIZK_verify_time"] = (end_time2 - start_time2)*1000
        print("[Client] NIZK_verify_time:", run_time["NIZK_verify_time"])
        ####################################NIZK.verify完成！！！###################################################

        ####################################加密和密钥封装###################################################
        # m = 'This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.This is a secret message.111111111111111111111111111'
        start_time3 = time.time()
        ek, k = opakem_encapsulation(y_prime_mid)
        end_time3 = time.time()
        run_time["opakem_encaps_time"] = (end_time3 - start_time3)*1000
        print("opakem_encapsulation passed")

        start_time4 = time.time()
        with open(source_file_path, 'rb') as f_in:
            m = f_in.read()
        # assert len(m) >= 10 * 1024 * 1024, "读取的数据小于10MB"
        print("len(m): ", len(m))
        c, tag = aes_gcm_encrypt(point_to_256bits(k), m, iv)
        print("len(c): ", len(c))
        end_time4 = time.time()
        enc_time = (end_time4 - start_time4) * 1000
        run_time["enc_time"] = enc_time
        print("[Client] encryption_time (s):", enc_time)

        start_time5 = time.time()
        payload = {'ek': ek, 'uid': uid_prime, 'mid': mid_prime, 'tag': tag}

        com_bytes =send_with_length(s, payload)
        communication_scale_enc += com_bytes
        com_bytes =send_with_length(s, c)
        communication_scale_enc += com_bytes

        ack,com_bytes =recv_with_length(s)####
        communication_scale_enc += com_bytes
        end_time5 = time.time()
        send_time = (end_time5 - start_time5) * 1000
        run_time["send_time"] = send_time
        print("[Client] send_time:", send_time)

        total_encryption_time = (end_time5 - start_time1)*1000
        run_time["total_encryption_time"] = total_encryption_time
        print("[Client] encryption time:", total_encryption_time)

        run_time["communication_scale_enc"] = communication_scale_enc
        # print("[Client] Sent encryption payload:", payload)
        ####################################加密和密钥封装完成！！！！###################################################
def client_run_dec(uid_prime, mid_prime, pw_prime,iv,run_time):
    HOST = '10.102.104.8'
    PORT = 25555

    # HOST = '127.0.0.1'
    # PORT = 20202
    #
    # HOST = '54.250.191.84'
    # PORT = 20202
    communication_scale_dec = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        try:
            s.connect((HOST, PORT))
        except Exception as e:
            print(f"[Client] Failed to connect to server: {e}")
            return

        print(f"Dec enter socket.connect!")

        start_time1 = time.time()
        payload = {'type': '3'}

        com_bytes =send_with_length(s, payload)
        communication_scale_dec += com_bytes

        ####################################解密###################################################
        # C和S运行解密

        # C和S运行opakem_token
        r_0 = generate_sk()
        a_0 = r_0 * H1(pw_prime)

        payload = {'uid_prime': uid_prime, 'mid_prime': mid_prime, 'a_0': a_0}
        com_bytes = send_with_length(s, payload)
        communication_scale_dec += com_bytes

        payload,com_bytes = recv_with_length(s)
        communication_scale_dec += com_bytes
        a_1 = payload['a_1']
        a_1m = payload['a_1m']
        sid = payload['sid']

        a_2 = inv(r_0) * a_1
        a_2m = inv(r_0) * a_1m
        y = H3(uid_prime+sid, pw_prime, a_2)
        y_mid = H3(uid_prime+sid, pw_prime, a_2m)
        end_time1 = time.time()
        OPaKEM_Token_time = (end_time1 - start_time1)*1000
        run_time["OPaKEM_Token_time"] = OPaKEM_Token_time
        print("[Client] OPaKEM_Token_time:", OPaKEM_Token_time)

        start_time2 = time.time()
        Str_rec,com_bytes = recv_with_length(s)
        communication_scale_dec += com_bytes
        c_rec = Str_rec['c']
        tag = Str_rec['tag']
        ek = Str_rec['ek']
        end_time2 = time.time()
        retrieve_time = (end_time2 - start_time2)*1000
        run_time["retrieve_time"] = retrieve_time
        print("[Client] retrieve_time:", retrieve_time)

        start_time3 = time.time()
        k_prime = opakem_decapsulation(y_mid, ek)
        print("k_prime:", point_to_str(k_prime))
        end_time3 = time.time()
        OPaKE_decaps_time = (end_time3 - start_time3)*1000
        run_time["OPaKEM_decaps_time"] = OPaKE_decaps_time
        print("[Client] OPaKE_decaps_time:", OPaKE_decaps_time)


        start_time4 = time.time()
        # C运行aes_gcm_decrypt
        m_prime = bytes_to_str(aes_gcm_decrypt(point_to_256bits(k_prime), c_rec, tag, iv))
        print("len(m_prime): ", len(m_prime))
        # print("m_prime:", m_prime)
        print("解密完成！")
        end_time4 = time.time()
        dec_time=(end_time4 - start_time4)*1000
        run_time["dec_time"] = dec_time
        print("[Client] Dec time:", dec_time)
        run_time["total_decryption_time"] = (end_time4 - start_time1)*1000
        print("[Client] total_decryption_time:", run_time["total_decryption_time"])

        run_time["communication_scale_dec"] = communication_scale_dec
        # print("[Client] Sent decryption payload:", payload)



