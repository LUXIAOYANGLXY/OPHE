import socket
import pickle
from Crypto.Random import get_random_bytes
from TwinStore1 import *
import socket
import pickle
from Crypto.Random import get_random_bytes
from utils import *

g = generator


def server_run_register(s, Reg,run_time,sid):
    print("Server is running...")
    # 这里可以添加服务器的具体逻辑
    with s:

        start_time1 = time.time()
        ###setup初始化
        sk, Str, Reg1 = twinstore_setup()
        # print("Reg", Reg)


        ###注册 opa_register11############################################################################

        payload=recv_with_length0(s) #接收uid和a0
        uid = payload['uid']
        a_0 = payload['a_0']

        a_1 = inv((sk + H2(str_to_bytes(uid+sid))) % order) * a_0
        print("[Server] Generated a_1:", point_to_str(a_1))

        payload = {'sid': sid, 'a_1': a_1}
        send_with_length0(s,payload) # 发送uid和a0
        cy = recv_with_length0(s)

        Reg[uid] = {
            'uid': uid,
            'cy': cy,
            'sk': sk
        }

        print("注册完成！Reg", Reg)
        end_time1 = time.time()
        register_time = (end_time1- start_time1) * 1000
        run_time["register_time"] = register_time
        print("[Server] register_time:", register_time)
        #####################################注册完成！！！！！######################################################



def server_run_enc(s, Reg,Str,run_time,sid):
        #########数据加密和对秘钥的封装###################################################################################################

        ####C与S运行opa_authenticate11######################################################################################
        start_time1 = time.time()
        payload = recv_with_length0(s)
        uid_prime = payload['uid_prime']
        mid_prime = payload['mid_prime']
        a_0_prime = payload['a_0_prime']
        b = payload['b']
        print ("Reg:", Reg)

        if uid_prime in Reg:
            a_1_prime = inv((Reg[uid_prime]['sk'] + H2(str_to_bytes(uid_prime+sid))) % order) * a_0_prime
            a_1_prime_mid = inv((Reg[uid_prime]['sk']  + H2(str_to_bytes(uid_prime+sid + mid_prime))) % order) * a_0_prime
            c_m = generate_sk()
        else:
            print("用户未注册，请检查")
            return

        payload = {'a_1_prime': a_1_prime, 'a_1_prime_mid': a_1_prime_mid, 'c_m': c_m, 'sid':sid}
        send_with_length0(s, payload)

        r_c=recv_with_length0(s)

        left = r_c * generator
        right = b + c_m * Reg[uid_prime]['cy']
        print(" left = " + point_to_str(left))
        print("right = " + point_to_str(right))
        if left == right:
            send_with_length0(s, '1')
            print("认证通过")
        else:
            send_with_length0(s, '0')
            print("认证失败")
        # print("Authentication " + "Passed" if left == right else "Failed")
        end_time1 = time.time()
        Authentication_time = (end_time1 - start_time1) * 1000
        run_time["opa_Authentication_time"] = Authentication_time
        print("[Server] opa_Authentication_time:", Authentication_time)
        ####################################认证通过################################################

        ####################################NIZK.prove###################################################
        start_time2 = time.time()
        v = H2(str_to_bytes(uid_prime+sid + mid_prime))
        w = (Reg[uid_prime]['sk']  + v) % order
        gw = generate_pk(w)
        pk = generate_pk(Reg[uid_prime]['sk'] )
        # S运行NIZK.prove
        pi = nizk_prove(Reg[uid_prime]['sk'] , uid_prime, mid_prime, g, gw, a_1_prime_mid, a_0_prime,sid)  ##########
        payload = {'pk':pk,'pi': pi}
        send_with_length0(s, payload)
        end_time2 = time.time()
        NIZK_prove_time = (end_time2 - start_time2) * 1000
        run_time["NIZK_prove_time"] = NIZK_prove_time
        print("[Server] NIZK_prove_time:", NIZK_prove_time)
        ####################################NIZK.prove完成！！！！！###################################################

        ####################################存储密文###################################################
        start_time3 = time.time()
        payload = recv_with_length0(s)
        ek = payload['ek']
        mid_prime = payload['mid']
        uid_prime = payload['uid']
        tag = payload['tag']
        c = recv_with_length0(s)
        Str[uid_prime,mid_prime] = {
            'uid': uid_prime,
            'mid': mid_prime,
            'ek': ek,
            'tag': tag,
            'c': c
        }
        send_with_length0(s, '1')
        print("存储密文完成！Str")
        end_time3 = time.time()
        receive_store_time = (end_time3 - start_time3) * 1000
        run_time["receive_store_time"] = receive_store_time
        print("[Server] receive_store_time:", receive_store_time)

        total_encryption_time = (end_time3 - start_time1) * 1000
        run_time["total_encryption_time"] = total_encryption_time
        print("[Server] total_encryption_time:", total_encryption_time)
        ####################################存储密文成功！！！###################################################

def server_run_dec(s,Reg, Str,run_time,sid):
        ####################################客户端申请解密###################################################
        start_time1 = time.time()
        # C和S运行opakem_token
        payload = recv_with_length0(s)
        uid_prime = payload['uid_prime']
        mid_prime = payload['mid_prime']
        a_0= payload['a_0']
        print("uid_prime:", uid_prime)
        print("mid_prime:", mid_prime)
        # print("Str:", Str)
        if (uid_prime,mid_prime) not in Str:
            print("用户未注册，请检查")
            return None
        a_1 = inv((Reg[uid_prime]['sk'] + H2(str_to_bytes(uid_prime))) % order) * a_0
        a_1m = inv((Reg[uid_prime]['sk']+ H2(str_to_bytes(uid_prime + mid_prime))) % order) * a_0
        end_time1 = time.time()
        OPaKEM_Token_time = (end_time1 - start_time1) * 1000
        run_time["OPaKEM_Token_time"] = OPaKEM_Token_time
        print("[Server] OPaKEM_Token_time:", OPaKEM_Token_time)

        start_time2 = time.time()
        payload = {'a_1': a_1, 'a_1m': a_1m, 'sid':sid}
        send_with_length0(s, payload)

        send_with_length0(s, Str[uid_prime,mid_prime])
        end_time2 = time.time()
        send_time = (end_time2 - start_time2) * 1000
        run_time["send_time"] = send_time
        print("[Server] send_time:", send_time)
        total_encryption_time = (end_time2 - start_time1) * 1000
        run_time["total_decryption_time"] = total_encryption_time
        print("[Server] total_decryption_time:", total_encryption_time)
        print("数据已传输√")




















