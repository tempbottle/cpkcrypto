# Introduction #
This project provides a identity-based cryptography toolkit based on the CPK (Combined Public Key) cryptography algorithm. The foundation of this project is the CPK algorithm. CPK is one type of Identity Based Cryptography (IBC), which is public key cryptography that the public key can be an arbitrary string such as an email address, a user name, or a phone number. The concept of taking identity or identifier as public key was introduced to eliminate the complexity of public key and certificate management. The CPK algorithm is one of the implementations of IBC that was invented by Xianghao Nan.

## CPK Algorithm ##
The advantage of CPK can be seen from a scenario that Alice wants to send a secret message to Bob with email address ''bob@company.com''. With traditional public key techniques such as PKI (Public Key Infrastructure) or PGP (Pretty Good Privacy), Alice must get Bob's public key from a online public key database such as LDAP (Lightweight Directory Access Protocol) server or from a trusted web page before she can encrypt the message. On the contrary, with CPK Alice just simply encrypts the message with bob's email address ''bob@company.com'' by an identity based encryption scheme without the public key retrieving procedure.

## CPK Command Line Tool ##

This is a command line tool that implement the **System Setup**, **Private key extraction**, **Sign/Verify**, **Encrypt/Decrypt** and **Data format parsing** functions.

We provide CPK command line tool for many platforms including Windows, Linux, OS X and even Android. You can download the version for your platform and copy the executable binary to the default path.

To initialize this cryptographic system, at first you need to import the system public parameters, setup your own identity and request the corresponding private key. You can download the default public parameters [public\_params.der](http://cpkcrypto.googlecode.com/files/public_params.der), and then import it with the following command:
```
$ cpk -import-param -in public_param.der
```
The next step is to set your identity and import your private keys. The identity can be any type of string, while currently we only generate private keys for internet users with email address as identity. You can write a letter to the owner of this project (guanzhi1980) to request the corresponding private key. The private key will be mail to you in 2 days. We also provide two example private keys ( [alice@cpksecurity.com](http://code.google.com/p/cpkcrypto/downloads/detail?name=alice.pem), [bob@cpksecurity.com](http://code.google.com/p/cpkcrypto/downloads/detail?name=bob.pem)) for testing.
```
$ cpk -set-identity alice@cpksecurity.com
$ cpk -import-sign-key -in alice.pem
$ cpk -import-decrypt-key -in alice.pem
```
The default password is "12345678". You can change the password after the import with command:
```
$cpk -change-sign-password
$cpk -change-decrypt-password
```

You can use the command line tool to encrypt/sign text or file.

```
$ echo "hello world" | cpk -sign
$ echo "hello world" | cpk -verify <signature> -signer alice@cpksecurity.com
```

You can encrypt message to multiple recipients

```
$ cpk -encrypt -in document.txt -to alice@cpksecurity.com -to bob@cpksecurity.com -out document.txt.cpk

$ cpk -decrypt -in document.txt.cpk
```

## CPK Browser Plugin (new!) ##

![http://cpkcrypto.googlecode.com/files/Screenshot-Web%20Browser%20Crypto%20Plugin%20-%20Mozilla%20Firefox.png](http://cpkcrypto.googlecode.com/files/Screenshot-Web%20Browser%20Crypto%20Plugin%20-%20Mozilla%20Firefox.png)

