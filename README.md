GO Remote Desktop Gateway
=========================

:star: Star us on GitHub — it helps!

RDPGW is an implementation of the [Remote Desktop Gateway protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/0007d661-a86d-4e8f-89f7-7f77f8824188).
This allows you connect with the official Microsoft clients to remote desktops that are made available over HTTPS. 
These desktops could be, for example, [XRDP](http://www.xrdp.org) desktops running in containers
on Kubernetes.

## AIM
RDPGW aims to provide a full open source replacement for MS Remote Desktop Gateway, 
including access policies.

## TODO
* Integrate VIPER
* Integrate Open Policy Agent
* Integrate GOKRB5
* Integrate uber-go/zap
* Integrate prometheus
* Research: TLS defragmentation 

## How to build
go build rdg.go main.go http.go errors.go

## How to run
Make sure you have a certificate and key file available. You can call those server.pem and key.pem and 
put them in the same directory as your executable.

./rdg
