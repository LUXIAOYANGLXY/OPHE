**Description**


The TwinStore system can securely store data in the cloud and manage corresponding keys.

Our implementation includes a client and a server; the server is implemented using both a local server or an AWS EC2 server.
Users can encrypt, store, and decrypt data, as well as manage keys.


**Installation**

Download the full repository fot both the client and server.

**Requirements**

Software requirements on both client and server:

* Python

Hardware requirement to the client:

* Local server and AWS EC2 instance. Please first log in to the AWS console via https://aws.amazon.com/ using your own AWS account, and create security credentials to access AWS EC2 instances programmatically, obtaining an access key.
* The client and key server could be deployed on different devices for standard use. It is ok to run two processes for the client and key server in one device to verify the function.

**Preparation** 

Access the server through IP address and port number. Switch between local server and AWS E2 server by modifying the IP address and port number.

**test datasets**

The test data consists of binary files ranging from 1MB to 1000MB.

Generation operation of test dataset:

To open a terminal and generate an nMB file, the command is as follows: fsutil file createnew 1*nmb 1048576*n


**Run**

Python [main] [server]

Terminal 1：python TwinStore1_main.py server 

Python [main] [client] [source file path]

Terminal 2：python TwinStore1_main.py client \DataFile\1mb



**Test**

The specific content of the experiment can be found in the test_readme.txt file.



