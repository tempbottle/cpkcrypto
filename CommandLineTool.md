# Introduction #

This is a command line tool that implement the **System Setup**, **Private key
extraction**, **Sign/Verify**, **Encrypt/Decrypt** and **Data format parsing** func-
tions.

The output ﬁle format of ‘cpk’ is ASN.1 DER encoded and similar to
PKCS#7 SignerInfo and RecipientInfo. These output can be parsed by other
tools that supporting the parse of DER ﬁles, for example, ‘openssl asn1parse’
command. A revision of this tool with C API has been integrated into a e-banking
system in Minsheng Commercial Band for enterprise customers.


### System Setup ###

```
cpk gen-secmatrix --ec secp192k1 --col 32 --row 32 --map-algo SHA1 --out matrix.skm
```

```
cpk gen-pubmatrix --in matrix.skm --out matrix.pkm	
```



```
cpk sign    [--detach] [--key file | --token dev] [--keyid id] 
            [--sign-algo name] [--armor] [--in file] [--append-to file] 
            [--outform name] [--out file]
cpk verfiy  [options]
cpk encrypt [options]
cpk decrypt [options]
cpk parse   [--inform name] [--in file] [--out file]
cpk help    [name]
```



```
cpk gen-key --id yourname --in matrix.skm > yourname.skey
```

```
cpk sign --key yourname.skey --in document.txt > document.txt.sig
cpk verify --matrix matrix.pkm --signed-file document.txt 
        --sig-file document.txt.sig
echo a-session-key | cpk encrypt --detach --matrix matrix.pkm 
        --recipient rcpt-name > symmkey.cpk
cpk decrypt --key yourname.skey --in cipher.cpk > plain
```





## Test Scripts ##

```
#!/bin/sh

line='-------------------------------------------------------'


echo 'CPK TOOLKIT TEST SCRIPT 0.6.7a'
echo '-------------------------------------------------------'

./cpk version
echo ''


#echo $line 
#echo 'Generate private matrix:'
#gensecmat='./cpk gen-secmatrix --ec secp192k1 --col 32 --row 32 --map-algo SHA1 --out secmatrix.cpk'
#echo $gensecmat
#$gensecmat
#echo ''


#echo $line
#echo 'Display genereated private matrix:'
#showsecmat='./cpk parse --type PrivateMatrix --in secmatrix.cpk'
#echo $showsecmat
#$showsecmat
#echo ''

echo $line
echo 'Derive public matrix from generated private matrix:'
genpubmat='./cpk gen-pubmatrix --in secmatrix.cpk --out pubmatrix.cpk'
echo $genpubmat
$genpubmat
echo ''

echo $line
echo 'Display public matrix:'
showpubmat='./cpk parse --type PublicMatrix --in pubmatrix.cpk'
echo $showpubmat
$showpubmat
echo ''

echo $line
echo 'Generate private key (id certificate) for alice@infosec.pku.edu.cn:'
genkey1='./cpk gen-key --id alice@infosec.pku.edu.cn --in secmatrix.cpk --out alice.idc'
echo $genkey1
$genkey1
echo ''

echo $line
echo 'Generate private key (id certificate) for bob@infosec.pku.edu.cn:'
genkey2='./cpk gen-key --id bob@infosec.pku.edu.cn --in secmatrix.cpk --out bob.idc'
echo $genkey2
$genkey2
echo ''

echo $line
echo 'Display generated private keys:'
showkey1='./cpk parse --type PrivateKey --in alice.idc'
echo $showkey1
showkey2='./cpk parse --type PrivateKey --in bob.idc'
echo $showkey2
$showkey1
$showkey2
echo ''

echo $line
echo '[This is a plaintext.]' > text
echo 'Content of plaintest file <text> is:'
cat text
echo ''

echo $line
echo 'Alice sign <text> with her private key:'
sign='./cpk sign --detach --key alice.idc --in text --out text.sig'
echo $sign
$sign

showsig='./cpk parse --type SignerInfo --in text.sig'
echo $showsig
$showsig
echo ''

echo $line
echo 'Bob verify <text.sig> with public matrix:'
verify='./cpk verify --matrix pubmatrix.cpk --signed-file text --sig-file text.sig'
echo $verify
$verify
echo ''


echo $line
echo 'Alice encrypt a session key file <text> to Bob with public matrix:'
encrypt='./cpk encrypt --detach --matrix pubmatrix.cpk --recipient bob@infosec.pku.edu.cn --in text --out text.enc'
echo $encrypt
$encrypt

showenc='./cpk parse --type RecipientInfo --in text.enc'
echo $showenc
$showenc
echo ''


echo $line
echo 'Bob decrypt the <text.enc> with his private key and display it:'
decrypt='./cpk decrypt --key bob.idc --in text.enc'
echo $decrypt
$decrypt
echo ''

echo 'Test finished.'
echo ''

```