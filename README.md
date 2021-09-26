# memcached-sgx

A port of memcached into Intel SGX. Meant for benchmarking configless switchless calls.

## How to test memcached-sgx (Ubuntu 18.04)

- Install SGX SDK on your system
```
./sgx-install.sh

```

- Install the following libraries

```
sudo apt-get install libseccomp-dev
sudo apt-get install libsasl2-dev

```
- Download libevent [here](https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz)
- If in cmd-line mode: 

```
sudo apt-get install wget
wget https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz
```
- Build and install libevent

```
tar -xvf libevent*
cd libevent*
./autogen.sh
./configure
make
sudo make install

```
- Add libevent symbolic link. The below command works only for the above installed libevent version. Modify the command accordingly if you have a different version of libevent installed.

```
sudo ln -s /usr/local/lib/libevent-2.1.so.7 /usr/lib/libevent-2.1.so.7

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
./memcached-sgx

```

- NB: this version does not kill the process/threads correctly with `ctrl + c`. Kill the app with the kill script `./kill.sh` or run app in the sgx-gdb debugger and stop normally via ctrl + c. To run app in the sgx debugger, do:

```
source /opt/intel/sgxsdk/environment 
sgx-gdb ./memcached-sgx

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

## Benchmarking with YCSB workloads
- Follow these instructions to test memcached with YCSB workloads.

- Start by installing java and maven on your server if they are absent.

```
sudo apt update
sudo apt install default-jre
sudo apt install maven

```
- Setup YCSB.

```
cd YCSB
mvn -pl site.ycsb:memcached-binding -am clean package

```
- Launch the memcached-server as explained above: either `memcached-sgx` or default `memcached`.

- Load YCSB data (ie kv pairs) into the memcached server. We use workload A in this example. 

```
./bin/ycsb load memcached -s -P workloads/workloada -p "memcached.hosts=127.0.0.1" -threads 4 > outputLoad.txt

```
- Run operations (ie get/set/) on the loaded memcached server. This will use 4 client threads; modify the option to change. The output of the run is sent to `outputRun.txt`

```
./bin/ycsb run memcached -s -P workloads/workloada -p "memcached.hosts=127.0.0.1" -threads 4 > outputRun.txt

```
