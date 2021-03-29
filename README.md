## 1-To-n Oblivious Transfer protocol based on ElGamal Cryptosystem
### What is an Oblivious Transfer
An Oblivious Transfer (OT) is a protocol between a sender *S* and a receiver *R* that allows *R* to obtain a message m<sub>i</sub> from a set of messages M = {m<sub>0</sub>,...,m<sub>n</sub>} held by *S* without *S* learning which message *R* obtained and with *R* only learning m<sub>i</sub> and no other messages in M. <br>
OT protocols have applications in areas such as secure multiparty computation and private set intersection.<br>
It this project, a *pure Rust Implementation* of a 1-to-n OT protocol based on ElGamal Cryptosystem is implemented.

### Preliminaries
#### ElGamal Cryptosystem
Given a cyclic group *G* of prime order *n* and one of its generator *g*, ElGamal Cryptosystem is a triple of polynomial time algorithms **(Gen, Enc, Dec)** with the following properties:
- The key generation algorithm **Gen** samples at random a value *x* belonging to the set *Z*<sup>*</sup><sub>n</sub>(set of integers using modular *n* arithmetic, i.e., modulo *n* is applied on all operations) and computes *y*=*g*<sup>x</sup> *mod n*. The value *x* is the secret key and the value *y* is the public key. 
- The encryption algorithm **Enc** takes as input a public key *y* and a message *m* belonging to the group *G*. Then, it samples at random a secret value *r* belonging to *Z*<sup>*</sup><sub>n</sub>. After, it computes *c*<sub>1</sub> = *g*<sup>r</sup> *mod n* and *c*<sub>2</sub> = m.*y*<sup>r</sup> *mod n* = m.*g*<sup>x.r</sup> *mod n*. Finally, it outpus (*c*<sub>1</sub>, *c*<sub>2</sub>).
- The decryption algorithm **Dec** takes as inputs a secret key *x* and a tuple of ciphertexts (*c*<sub>1</sub>, *c*<sub>2</sub>). Then, it computes *k* = *c*<sub>1</sub><sup>x</sup>*mod n* = *g*<sup>x.r</sup> *mod n*. Using *k*, it computes *m* = *c*<sub>2</sub>.*k*<sup>-1</sup>*mod n* = m.*g*<sup>x.r</sup>.*g*<sup>-(x.r)</sup> *mod n*
#### The protocol
Following is a diagram that depicts the execution of the protocol:
![protocol](miscellaneous/protocol.png)
### How to run (Linux)
Have the following components installed:
1. Rust >= version 1.45
2. OpenSSL >= version 1.1.1
<br>
Once the different environment dependencies have been installed, create an RSA private key and a signed 
certificate for the server (both in PEM format) using OpenSSL and place those files in
src/keyfile folder.<br>

Next, With the terminal working directory set to the project director, run the command `cargo build --release` <br>

* To launch the Server/Sender program, executes the command `./target/release/server`
* To launch the Client/Receiver program, executes the command `./target/release/client`

### Output example
Following is an example between a client and a server:
![Example](miscellaneous/exampleE.png)
As we can see, The client selected message at index 3, and after, it is only able to obtain a plaintext version of message at index 3.

Thus, 1-n OT protocol is respected.

### Reference
1. D. Boneh and V. Shoup, ["A Graduate Course in Applied Cryptography"](https://toc.cryptobook.us/), Chapter 11
