import pickle
import sys
import socket
import configparser
from wsgiref.simple_server import server_version
# from TwinStore1_server import server_run
from Crypto.Random import get_random_bytes
from TwinStore1_client_07 import client_run_register,client_run_enc,client_run_dec
from TwinStore1_server_07 import server_run_enc,server_run_register, server_run_dec
from utils import *


def main():
    # uid = "id"
    # pw = "passw0rd"
    # mid = "session_id"

    if len(sys.argv) == 1:
        print("第一个参数：client/authserver")
        print("如果第一个参数是 client，第二个参数是源文件路径")
        return

    role = sys.argv[1]
    print(role)

    Reg = {}  # 初始化注册表
    Str = {}  # 初始化字符串表

    if role == "client":
        print("客户端测试整个流程")
        source_file_path = sys.argv[2]
        print(f"源文件路径为：{source_file_path}")

        metrics_total = {
            "register_time": 0,
            "opa_authentication_time":0,
            "NIZK_verify_time":0,
            "opakem_encaps_time":0,
            "enc_time": 0,
            "send_time":0,
            "total_encryption_time":0,
            "OPaKEM_Token_time":0,
            "retrieve_time": 0,
            "OPaKEM_decaps_time": 0,
            "dec_time":0,
            "total_decryption_time": 0,
            "communication_scale_register":0,
            'communication_scale_enc': 0,
            'communication_scale_dec': 0
        }

        run_time = {}

        for i in range(10):
            print(f"\n=========== 第 {i + 1} 次测试 ===========")
            uid = '1235456'
            mid = '456123'
            pw = '6666666'
            iv = get_random_bytes(12)
            client_run_register(uid, pw,run_time)

            uid_prime = "1235456"
            mid_prime = "456123"
            pw_prime = "6666666"
            client_run_enc(uid_prime, mid_prime, pw_prime, source_file_path,iv,run_time)

            uid_prime = "1235456"
            mid_prime = "456123"
            pw_prime = "6666666"
            client_run_dec(uid_prime, mid_prime, pw_prime,iv,run_time)

            for key in metrics_total:
                if key in run_time:
                    metrics_total[key] += run_time[key]
                else:
                    print(f"⚠️ Warning: 第{i + 1}次测试未记录指标 {key}")
        print("\n======== 📊 平均耗时统计（单位：ms）========")
        for key in metrics_total:
            avg_time = metrics_total[key] / 10
            print(f"{key}: {avg_time:.2f} ms")
    elif role == "server":

        PORT = 25555
        # PORT = 20202
        metrics_total = {
            "register_time": 0,
            "opa_Authentication_time": 0,
            "NIZK_prove_time": 0,
            "receive_store_time": 0,
            "total_encryption_time": 0,
            "OPaKEM_Token_time": 0,
            "send_time": 0,
            "total_decryption_time": 0
        }

        run_time = {}

        with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            s.bind(('', PORT))  # 绑定主机地址和端口号
            s.listen()  # 监听传入的连接请求
            print("[Server] Waiting for connection...")
            sid = "9658324"

            try:
                while True:
                    i = 0
                    print(f"\n=========== 第 {i + 1} 次测试 ===========")
                    conn, addr = s.accept()
                    request = recv_with_length0(conn)
                    if request['type'] == '1':
                        print("\n[SERVER] 等待客户端注册...\n")
                        server_run_register(conn, Reg,run_time,sid)
                    elif request['type'] == '2':
                        print("\n[SERVER] 等待客户端加密传输...\n")
                        server_run_enc(conn, Reg,Str,run_time,sid)
                    elif request['type'] == '3':
                        print("[SERVER] 等待客户端解密传输...\n")
                        server_run_dec(conn, Reg,Str,run_time,sid)
                    for key in metrics_total:
                        if key in run_time:
                            metrics_total[key] += run_time[key]
                        else:
                            print(f"⚠️ Warning: 第{i + 1}次测试未记录指标 {key}")
                    for key in metrics_total:
                        avg_time = metrics_total[key] / 10
                        print(f"{key}: {avg_time:.2f} ")

                    # server_run(conn, addr)
            finally:
                s.close()

if __name__ == '__main__':
    main()