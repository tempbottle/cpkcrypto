# this page gives the examples of the CPKjava cmdline utility.

# Introduction #

Though called an utility, the parameters of the CPKjava cmdline are not completely self-explanatory even for the experts. To alleviate this, I will add the examples for some hard-to-understand parameters later. For now, you could take a look at the examples below for a bypass.

# Examples for CPKjava #

For now, CPKjava has the sub-commands below:
  * **gen-secmatrix**, generate the secmatrix, which is used to generate private keys
  * **gen-pubmatrix**, generate the pubmatrix, which is used to generate public keys
  * **sign**, sign a file, you will need the private key
  * **verify**, verify a signature against the original file, the pubmatrix is needed
  * **encrypt**, encrypt a file; private key, pubmatrix, recipient's ID are needed
  * **decrypt**, decrypt a file; private key, pubmatrix, sender's ID are needed
  * **gen-key**, given the ID, return the private key, secmatrix is needed
  * **help**, show this

Let's check them out one-by-one.

### 1. gen-secmatrix ###
```
usage: gen-secmatrix
    --col <col_number>     the count of column of the secmatrix
    --ec <ec_curve_name>   specify an named ec curve
    --map-algo <algName>   the name of the id->key mapping algorithm
    --out <matrixFile>     specify the file name for exported secret
                           matrix
    --row <row_number>     the count of row of the secmatrix
```

If you have experienced other cmdline stuff, I think this piece won't panic you at all. However without knowing some details here, I think you cannot go any further._(Yes, I know, it's my fault. I should have written the default by the side)_
  * the **row** and **col** are paramters for matrix, don't let the product exceed 512 for now.
  * **ec** is the name for a elliptic curve, you could check the list out from openssl or web, or simply a _secp192k1_ will do.
  * **out** where to put the generated secmatrix
  * **map-algo** this place is used for extension of mapping algorithm. If you want to know the details, check out the source code; or just put the _DigestMap\_SHA512_ here.

```
CPKcmd gen-secmatrix --col 32 --row 16 --ec secp192k1 --map-algo DigestMap_SHA512 --out secmatrix
```


---

### 2. gen-pubmatrix ###
```
usage: gen-pubmatrix
    --in <secmatrixFile>    the filename of secret matrix previously
                            exported
    --out <pubmatrixFile>   the name of file where public matrix to be
                            exported
```

The pubmatrix is simply derived from the secmatrix.
  * **in** put the just generated _secmatrix_ here
  * **out** tell it where to put the _pubmatrix_

```
CPKcmd gen-pubmatrix --in secmatrix --out pubmatrix
```


---

### 3. gen-key ###
```
usage: gen-key
    --id <ID>                   the id used to generate the PrivateKey
    --in <secmatrix>            the file containing the secret matrix
    --out <privateKeyOutFile>   the file where PrivateKey to be exported
```

Before doing the sign/verify, en/decrypt operations, we must prepare our keypairs first!
Say we'll let Alice to sign/encrypt a file and let Bob to verify/decrypt it. We should generate the private keys for both of them here.
  * **id** derive key from ID, a core concept of IBC
  * **in** we need previously generated _secmatrix_ here
  * **out** where to put your new private key

```
CPKcmd gen-key --id Alice --in secmatrix --out alicekey
CPKcmd gen-key --id Bob --in secmatrix --out bobkey
```


---

### 4. sign ###
```
usage: sign
    --in <FileToBeSigned>    the file to be signed
    --key <privateKeyFile>   the file containing the PrivateKey used for
                             signing
    --keyid <signerId>       the signer's id
    --out <outputFile>       where the signature to be output
```

let's assume Alice wanna sign a file and let Bob to verify it later...

```
CPKcmd sign --in CPKcmd.exe --key alicekey --keyid Alice --out sig
```


---

### 5. verify ###
```
usage: verify
    --matrix <public_matrix_filename>   the filename of public matrix
    --sig-file <signatureFile>          the file containing signature
    --signed-file <signedFile>          the file got signed
```

Ok, it's Bob's turn. Verify the _sig_ against the original file _CPKcmd.exe_...

```
CPKcmd verify --matrix pubmatrix --sig-file sig --signed-file CPKcmd.exe
```


---

### 6. encrypt ###
```
usage: encrypt
    --in <FileToEncrypt>      the file according to which cipher text will
                              be generated
    --key <PrivateKey>        the file containing private key
    --out <outputFile>        the file where cipher text to be output
    --pubmatrix <pubmatrix>   the file containing public matrix
    --recipient <recipient>   the recipient of the cipher text
```

Alice wanna encrypt a file _'CPKcmd.exe'_ now, and asks poor Bob to decrypt it later. Yes, we know, she does this because she's Alice...

```
CPKcmd encrypt --in CPKcmd.exe --key alicekey --out encrypted --pubmatrix pubmatrix --recipient Bob
```


---

### 7. decrypt ###
```
usage: decrypt
    --in <cipherFile>         the file containing cipher text
    --key <PrivateKey>        the file containing private key
    --out <outputFile>        the file where cipher text to be output
    --pubmatrix <pubmatrix>   the file containing public matrix
    --sender <senderId>       the sender's ID
```

Bob has to decrypt the encrypted file now. (Nah, buddy. Don't ask me why you have to do this. It's Bob's **DESTINY**)

```
CPKcmd decrypt --in encrypted --key bobkey --out original.exe --pubmatrix pubmatrix --sender Alice
```

Ok, Bob should be able to run **original.exe** as though it's **CPKcmd.exe** now.


---


# End #