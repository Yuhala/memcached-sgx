# memcached-sgx

A port of memcached into Intel SGX. Meant for benchmarking configless switchless calls.

## How to test memcached-sgx (Ubuntu 18.04)

- Install SGX SDK on your system
```
./sgx-install.sh

```

- Install the following libraries

```
sudo apt install libseccomp-dev
sudo apt-get install libsasl2-dev
```
- Download, build and install libevent [here](https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz)

```
tar -xvf libevent*
cd libevent*
./autogen.sh
./configure
make
make install

```
- Clone this repo and move to branch `memcached-port`

```
git clone https://gitlab.com/Yuhala/memcached-sgx.git
git checkout memcached-port
cd sgx

```

- Build the memcached-sgx server program:

```
make 

```  

- Run the memcached-sgx server.
```
./app

```

- NB: this version does not kill the process/threads correctly with `ctrl + c`. Try killing with `kill -9 PID_of_app` or run app in the sgx-gdb debugger and stop normally via ctrl + c. To run app in the sgx debugger, do:

```
source /opt/intel/sgxsdk/environment 
sgx-gdb ./app

```

- Open a terminal and connect to the server

```
telnet 127.0.0.1 11211

```
- Set a kv pair within the telnet session

```
set test 0 100 5
hello

```
- Get kv pair within the telnet session

```
get test

```
- To build normal memcached, cd into the `memcached` folder and run `make`. Run the server with `./memcached`. Connect to the server via telnet as explained above.

