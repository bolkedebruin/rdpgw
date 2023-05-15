# Upgrading from 1.X to 2.0

In 2.0 the options for configuring client side RDP settings have been removed in favor of template file.
The template file is a RDP file that is used as a template for the connection. The template file is parsed 
and a few settings are replaced to ensure the client can connect to the server and the correct domain is used.

The format of the template file is as follows:

```
# <setting>:<type i or s>:<value>
domain:s:testdomain
connection type:i:2
```

The filename is set under `client > defaults`.
