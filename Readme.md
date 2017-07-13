# Introduction

A Simple file encrypt & decrypt demo using Intel SGX.

# Enviroment

## Install SGX driver，PSW，SDK

1.下载安装文件

https://01.org/zh/intel-software-guard-extensions/downloads

Intel(R) SGX driver: sgx_linux_x64_driver.bin
Intel(R) SGX PSW: sgx_linux_x64_psw_<version>.bin
Intel(R) SGX SDK: sgx_linux_x64_sdk_<version>.bin
--------------------------------------------------
Notice:
6th Generation Intel® Core™ Processor 或者更新
Bios使能Intel® SGX选项
--------------------------------------------------

$ sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev
$ sudo apt-get install build-essential

安装 icls-Client
https://registrationcenter.intel.com/en/forms/?productid=2859
$ sudo apt-get install alien
$ sudo alien --scripts iclsClient-1.45.449.12-1.x86_64.rpm
$ sudo dpkg -i iclsclient_1.45.449.12-2_amd64.deb

安装jhi
$ git clone https://github.com/01org/dynamic-application-loader-host-interface
$ sudo apt-get install uuid-dev libxml2-dev cmake
$ cmake .;make;sudo make install;sudo systemctl enable jhi


安装driver
$ sudo ./sgx_linux_x64_driver.bin

安装PSW
$ sudo ./sgx_linux_x64_psw_<version>.bin
确保aesmd服务启动

安装SDK
$ ./sgx_linux_x64_sdk_<version>.bin
添加环境变量
将sdk安装完成后目录下的enviroment文件内容添加到".bashrc"

 
# Notice

This code can not be used for commercial purpose.
