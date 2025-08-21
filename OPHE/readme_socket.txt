#############code-ophe-socket通信版本##################
client和server可以在本地进行通信，修改ip地址和端口号后可实现【server运行在服务器、client运行在本地】的场景。
服务器的地址和端口号HOST = '10.102.104.8'，PORT = 25555


每个模块封装成函数：
NIZK.py ：NIZK协议
OPA1.py：论文中的Figure4
OPA2.py：论文中的Figure5
OPA11.py：在TwinStore1和TwinStore2中调用
OPAE1.py：论文中的Figure2
OPAE2.py：论文中的Figure2+灰色部分
OPaKEM.py：论文中4.2
Rotation.py：论文中的Figure3

通信：
TwinStore1.py：论文中的Figure6，无通信
[TwinStore1_main_07.py]：main函数
[TwinStore1_client_07.py]：客户端操作
[TwinStore1_server_07.py]：服务器操作
TwinStore2.py：论文中的Figure6+灰色字体部分，无通信
[TwinStore2_main_07.py]：main函数
[TwinStore2_client_07.py]：客户端操作
[TwinStore2_server_07.py]：服务器操作



通信版本调用方法：
Python [main] [server]
终端一：python TwinStore1_main.py server 
Python [main] [client] [源文件路径]
终端二：python TwinStore1_main.py client D:\Pycharm\Project\code-ophe-socket\1mb
