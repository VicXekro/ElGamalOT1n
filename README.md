## 1-To-n Oblivious Transfer protocol based on ElGamal Cryptosystem
### What is an Oblivious Transfer
### Description of the protocol
### How to run
#### Setup the environment
1. Rust >= version 1.45
2. OpenSSL >= version 1.1.1
Once the different environment dependencies have been installed, create an RSA private key and a signed 
certificate for the server (both in PEM format) using OpenSSL and place those files in
src/keyfile folder.
### Reference
1. D. Boneh and V. Shoup, ["A Graduate Course in Applied Cryptography"](https://toc.cryptobook.us/), Chapter 11
