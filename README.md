# Collection of scripts

## create_x509_chain

This bash script uses OpenSSL to generate a chain of X509 certificates in the
directory given in argument.

```console
Create a chain of X509 certificates.
Usage: ./create_x509_chain/create_x509_chain.sh LEAF_COMMON_NAME DIRECTORY
Example: ./create_x509_chain/create_x509_chain.sh foo.bar.com /home/foo/dir
```

For example, in order to create in the ./result directory the files *root.crt*,
*inter.crt* and *root.crt*.

```console
$ ./create_x509_chain/create_x509_chain.sh 192.168.0.1 ./result/
Generating RSA private key, 2048 bit long modulus (2 primes)
...........................................+++++
........................+++++
e is 65537 (0x010001)
Generating RSA private key, 2048 bit long modulus (2 primes)
.....+++++
...............+++++
e is 65537 (0x010001)
Using configuration from ./result//root.conf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
commonName            :ASN.1 12:'intermediate_certificate'
Certificate is to be certified until Oct 11 07:49:24 2020 GMT (30 days)

Write out database with 1 new entries
Data Base Updated
./result//inter.crt: OK
Generating RSA private key, 2048 bit long modulus (2 primes)
.....................+++++
....................................................................+++++
e is 65537 (0x010001)
Signature ok
subject=CN = 192.168.0.1
Getting CA Private Key
stdin: OK
$ ls ./result
BD4FD0207809F674A992095978D2F97D.pem  inter.pem  leaf.csr   root.crt         root.index.old  root.serial.old
inter.crt                             inter.srl  leaf.key   root.index       root.key
inter.csr                             leaf.crt   root.conf  root.index.attr  root.serial
```

## jira-cli

Dependencies: python3-jira, w3m
