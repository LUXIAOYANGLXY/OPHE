import socket
import pickle
from Crypto.Random import get_random_bytes
from TwinStore1 import *
import socket
import pickle
from Crypto.Random import get_random_bytes

from TwinStore1_server_07 import server_run_enc
from utils import *

g = generator

def server_run_register(s, Reg,run_time):
    print("Server is running...")
    # 这里可以添加服务器的具体逻辑
    with s:

        start_time1 = time.time()
        ###setup初始化
        sk, Str, Reg1 = twinstore_setup()
        print("Reg", Reg)
        # pk = generate_pk(sk)

        ###注册 opa_register11############################################################################

        payload = recv_with_length0(s)
        id = payload['id']
        a_0 = payload['a_0']

        a_1 = inv((sk + H2(str_to_bytes(id))) % order) * a_0
        print("[Server] Generated a_1:", point_to_str(a_1))

        send_with_length0(s, a_1)
        cy = recv_with_length0(s)

        Reg[id] = {
            'id': id,
            'cy': cy,
            'sk': sk
        }

        print("注册完成！Reg", Reg)
        end_time1 = time.time()
        register_time = (end_time1 - start_time1) * 1000
        run_time["register_time"] = register_time
        print("[Server] register_time:", register_time)
        #####################################注册完成！！！！！######################################################
def server_run_enc(s,Reg,Str,run_time):
        #########数据加密和对秘钥的封装###################################################################################################

        ####C与S运行opa_authenticate11######################################################################################
        start_time1 = time.time()
        payload = recv_with_length0(s)
        id_prime = payload['id_prime']
        mid_prime = payload['mid_prime']
        a_0_prime = payload['a_0_prime']
        b = payload['b']
        print("Reg:", Reg)

        if id_prime in Reg:
            a_1_prime = inv((Reg[id_prime]['sk'] + H2(str_to_bytes(id_prime))) % order) * a_0_prime
            a_1_prime_mid = inv((Reg[id_prime]['sk'] + H2(str_to_bytes(id_prime + mid_prime))) % order) * a_0_prime
            c_m = generate_sk()
        else:
            print("用户未注册，请检查")
            return

        payload = {'a_1_prime': a_1_prime, 'a_1_prime_mid': a_1_prime_mid, 'c_m': c_m}
        send_with_length0(s, payload)

        r_c = recv_with_length0(s)

        left = r_c * generator
        right = b + c_m * Reg[id_prime]['cy']
        print(" left = " + point_to_str(left))
        print("right = " + point_to_str(right))
        if left == right:
            send_with_length0(s, '1')
            print("认证通过")
        else:
            send_with_length0(s, '0')
            print("认证失败")
        end_time1 = time.time()
        Authentication_time = (end_time1 - start_time1) * 1000
        run_time["opa_Authentication_time"] = Authentication_time
        print("[Server] opa_Authentication_time:", Authentication_time)
        # print("Authentication " + "Passed" if left == right else "Failed")
        ####################################认证通过################################################

        ####################################NIZK.prove###################################################
        start_time2 = time.time()
        v = H2(str_to_bytes(id_prime + mid_prime))
        w = (Reg[id_prime]['sk'] + v) % order
        gw = generate_pk(w)
        pk = generate_pk(Reg[id_prime]['sk'])
        # S运行NIZK.prove
        pi = nizk_prove(Reg[id_prime]['sk'], id_prime, mid_prime, g, gw, a_1_prime_mid, a_0_prime)  ##########
        payload = {'pk': pk, 'pi': pi}
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
        id_prime = payload['id']
        tag = payload['tag']
        c = recv_with_length0(s)
        send_with_length0(s, '1')

        # ————————————————————————————————————————————————————灰色字迹—————————————————————————————————————————————————#
        b0 = recv_with_length0(s)
        b1 = b0 * Reg[id_prime]['sk']
        send_with_length0(s,b1)

        t = recv_with_length0(s)
        # ————————————————————————————————————————————————————灰色字迹—————————————————————————————————————————————————#

        Str[id_prime,mid_prime] = {
            'id': id_prime,
            'mid': mid_prime,
            'ek': ek,
            'tag': tag,
            'c': c,
            't': t
        }
        print("存储密文完成！Str")

        end_time3 = time.time()
        receive_store_time = (end_time3 - start_time3) * 1000
        run_time["receive_store_time"] = receive_store_time
        print("[Server] receive_store_time:", receive_store_time)

        total_encryption_time = (end_time3 - start_time1) * 1000
        run_time["total_encryption_time"] = total_encryption_time
        print("[Server] total_encryption_time:", total_encryption_time)
        ####################################存储密文成功！！！###################################################
def server_run_dec(s, Reg, Str,run_time):
        ####################################客户端申请解密###################################################
        start_time1 = time.time()
        # C和S运行opakem_token
        payload = recv_with_length0(s)
        id_prime = payload['id_prime']
        mid_prime = payload['mid_prime']
        a_0 = payload['a_0']
        if (id_prime,mid_prime) not in Str:
            print("用户未注册，请检查")
            return None
        a_1 = inv((Reg[id_prime]['sk']+ H2(str_to_bytes(id_prime))) % order) * a_0
        a_1m = inv((Reg[id_prime]['sk'] + H2(str_to_bytes(id_prime + mid_prime))) % order) * a_0
        r1_prime = generate_sk()
        b0_prime = r1_prime
        end_time1 = time.time()
        OPaKEM_Token_time = (end_time1 - start_time1) * 1000
        run_time["OPaKEM_Token_time"] = OPaKEM_Token_time
        print("[Server] OPaKEM_Token_time:", OPaKEM_Token_time)

        start_time2 = time.time()
        payload = {'a_1': a_1, 'a_1m': a_1m, 'b0_prime': b0_prime}
        send_with_length0(s, payload)

        send_with_length0(s, Str[id_prime,mid_prime])
        end_time2 = time.time()
        send_time = (end_time2 - start_time2) * 1000
        run_time["send_time"] = send_time
        print("[Server] send_time:", send_time)

        b1_prime = recv_with_length0(s)
        b2_prime = b1_prime * inv(r1_prime)
        k_prime_prime = Str[id_prime,mid_prime]['ek'] * inv(b2_prime)
        t_prime = H3(id_prime + mid_prime, point_to_str(Str[id_prime,mid_prime]['ek']), k_prime_prime * Reg[id_prime]['sk'])
        if Str[id_prime,mid_prime]['t'] == t_prime:
            send_with_length0(s,'1')
            print("OPAE解密成功")
        else:
            send_with_length0(s,'0')
            print("OPAE解密失败，t不匹配")
        end_time3 = time.time()

        total_encryption_time = (end_time3 - start_time1) * 1000
        run_time["total_decryption_time"] = total_encryption_time
        print("[Server] total_decryption_time:", total_encryption_time)
        ####################################数据检索成功###################################################


