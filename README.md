## memcached-sgx

A port of memcached into Intel SGX. This port was initially created for benchmarking an SGX-related project, but I ended up not using it. Since it works, I just decided to upload the code anyway, in case someone is interested in using.

> Disclaimer: this code most definitely contains some bugs or may not work out of the box. Please contact me in case you need some help.

## How to test memcached-sgx (Ubuntu 18.04)

- Install SGX SDK on your system
```bash
./sgx-install.sh

```

- Install the following libraries

```bash
sudo apt-get install libseccomp-dev
sudo apt-get install libsasl2-dev

```bash
- Download libevent [here](https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz)
- If in cmd-line mode: 

```bash
sudo apt-get install wget
wget https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz
```
- Build and install libevent

```bash
tar -xvf libevent*
cd libevent*
./autogen.sh
./configure
make
sudo make install

```
- Add libevent symbolic link. The below command works only for the above installed libevent version. Modify the command accordingly if you have a different version of libevent installed.

```bash
sudo ln -s /usr/local/lib/libevent-2.1.so.7 /usr/lib/libevent-2.1.so.7

```
- Clone this repo and move to branch `kyoto`

```bash
git clone https://gitlab.com/Yuhala/memcached-sgx.git
git checkout kyoto
cd sgx

```

- Build the memcached-sgx server program:

```bash
make 

```  

- Run the memcached-sgx server.
```bash
./memcached-sgx

```
- To run memcached-sgx server in Intel switchless mode, do:
```bash
./memcached-sgx 0 1

````

- NB: this version does not kill the process/threads correctly with `ctrl + c`. Kill the app with the kill script `./kill.sh` or run app in the sgx-gdb debugger and stop normally via ctrl + c. To run app in the sgx debugger, do:

```bash
source /opt/intel/sgxsdk/environment 
sgx-gdb ./memcached-sgx

```

- Open a terminal and connect to the server

```bash
telnet 127.0.0.1 11211

```
- Set a kv pair within the telnet session

```bash
set test 0 100 5
hello

```
- Get kv pair within the telnet session

```bash
get test

```
- To build normal memcached, cd into the `memcached` folder and run `make`. Run the server with `./memcached`. Connect to the server via telnet as explained above.


## Logging
- To view function call logs i.e names of enclave routines called in memcached-sgx, comment out `#undef LOG_FUNC_IN` in Enclave/memcached/my_logger_in.c
- To view function call logs for out-of-enclave routines called in memcached-sgx, comment out `#undef LOG_FUNC` in App/memcached/my_logger_out.c

## Benchmarking with YCSB workloads
- Follow these instructions to test memcached with YCSB workloads.

- Start by installing java and maven on your server if they are absent.

```bash
sudo apt update
sudo apt install default-jre
sudo apt install maven

```
- Setup YCSB.

```bash
cd YCSB
mvn -pl site.ycsb:memcached-binding -am clean package

```
- Launch the memcached-server as explained above: either `memcached-sgx` or default `memcached`.

- Load YCSB data (ie kv pairs) into the memcached server. We use workload A in this example. 

```bash
./bin/ycsb load memcached -s -P workloads/workloada -p "memcached.hosts=127.0.0.1" -threads 4 > outputLoad.txt

```
- Run operations (ie get/set/) on the loaded memcached server. This will use 4 client threads; modify the option to change. The output of the run is sent to `outputRun.txt`

```bash
./bin/ycsb run memcached -s -P workloads/workloada -p "memcached.hosts=127.0.0.1" -threads 4 > outputRun.txt

```

## Licensing
> I am yet to look at how open-source Licensing really works. For now, do whatever you want with my code, while respecting the license of any third-party code I have used. 

## Author
- [Peterson Yuhala]