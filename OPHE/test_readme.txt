TEST1: Test the running time of binary files of different sizes from 1mb, 10mb, 50mb to 200mb by running the code.

The test content includes registration time (register_time), encryption time (total_encryption_time), and decryption time (total_decryption_time).
The encryption time (total_encryption_time) includes the authentication time for OPA (opa_authentication_time), the verification time for NIZK (NIZK_ verification_time), the encryption time for OPAKEM (opakem_ encaps_time), and the encryption time for plaintext (enc_time), and other components.
The decryption time (total_decryption _time) includes the generation time of opakem's token (OPaKEM_Token_time), the decryption time of opakem (OPaKEM_decps_time), and the decryption time of the data ciphertext (dec_time), and other components.

Specific operating steps:
1. Run the server-side：python TwinStore1_main.py server
2. Run the client：python TwinStore1_main.py client \DataFile\1mb
3. Record experimental data;
4. Modify file size and run repeatedly;

We tested the running time on both local servers and AWS EC2 servers separately;
Server switching: Modify the IP address and port of the server connected to the client, and repeat the specific steps above.
# HOST = '127.0.0.1'
# PORT = 20202

Finally, analyze and summarize the recorded experimental data.

TEST2: Test the performance of opakem under different security parameters using OPaKEM_order.py;
1. Fix the length of the password to a 12 length string and modify the length of the security parameter.
2. The length of the fixed security parameter , and the length of the password can be modified.


