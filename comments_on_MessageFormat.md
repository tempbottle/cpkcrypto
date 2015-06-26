#this page explains some points of the wiki page of [MessageFormat](http://code.google.com/p/cpkcrypto/wiki/MessageFormats)

# 一. 概述 #

[MessageFormat](http://code.google.com/p/cpkcrypto/wiki/MessageFormats) 对CPK系统中使用的消息传输格式进行了比较详细的

列举，开发者可以尝试按照[CPK白皮书](http://cpkcrypto.googlecode.com/files/CPK%20Whitepaper.pdf)和MessageFormat wiki页

的标准来实现与CPK兼容的系统。

由于系统采用的多种数据格式都是来源于PKCS相关的RFC文档，且都使用了ASN.1的格式进行表示，对一些不熟悉PKCS和ASN.1的读者

来说可能会产生一定的理解困难，本页将对CPK系统采用的ASN.1的编码格式进行简单的介绍，此外还会针对涉及到的PKCS相关内容进

行扼要的解释。

# 二. 正文 #

Abstract Syntax Notation One（ASN.1）是一项用来描述数据格式，编码，传输，解码的灵活的标准，被广泛使用与电子通讯与计

算机网络中。ASN.1提供了一组形式化的规则来准确描述对象的结构，并且与平台架构无关，没有二义性。

ASN.1 最初在CCITT X.409:1984中被定义。之后ASN.1被单独移到了自己的标准X.208。之后由于其的广泛应用，又于1995年和2002年

重新修订过。

ASN.1 表示的数据格式当被写入磁盘或者要传输到网络上时，需要使用一种方式来进行编码。可以使用的编码方式很多`[1][2]`，包

括但不限于BER，DER，XER，PER。每种编码方式都有自己的特点，CPK系统中唯一地使用了DER编码方式，这种编码方式对于一个

ASN.1的结构具有唯一的表示方法。

接下来对CPK的ASN.1消息格式进行简要的分析。

### 1. OID ###
Object Identifier`[3]`，简称OID，是一组用来为对象命名的标识符。一个OID是由一组层次化的名字空间中的节点组成。例如：下

面的OID就用一组数字表示了SHA-1算法，每一个数字都代表名字空间中一个节点：
> sha-1 OBJECT IDENTIFIER ::= {iso(1) identified-organization(3) oiw(14) secsig(3) algorithm(2) 26}

如果用户想要建立一个新的节点，那么必须将其注册到一个registration authority。用户还可以在网上对已经注册过的节点和其内

容进行检索，比如可以去[OID Repository](http://www.oid-info.com)。

此外，像下面这样的表示方式，等于在已有的节点后面添加新节点，文档中有很多这样的表示方法，在此提请注意。
```
-- AES information object identifiers --
aes OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
        organization(1) gov(101) csor(3) nistAlgorithms(4)  1 }
-- AES using CBC-chaining mode for key sizes of 128, 192, 256
id-aes128-CBC OBJECT IDENTIFIER ::= { aes 2 }
id-aes192-CBC OBJECT IDENTIFIER ::= { aes 22 }
id-aes256-CBC OBJECT IDENTIFIER ::= { aes 42 }

```

### 2. ASN.1 常用表示类型 ###
ASN.1的表示系统中有一些比较常用的类型，理解了这些常用类型之后，CPK的消息格式基本上可以看懂很大一部分了。
首先是一些简单类型（Simple types）:
  * BIT STRING, 一组由二进制0，1组成的串.

  * IA5String, 一个IA5字符串，IA5指ascii

  * INTEGER, 一个整数值.

  * NULL, 一个NULL值.

  * OBJECT IDENTIFIER, 一个OID，由一组整数构成，用来标示一个算法或者属性类别

  * OCTET STRING, 一个由8bit字节构成的串.

  * PrintableString, 一个由任意可显示的字符构成的串.

  * T61String, 一个由8bit字节构成的串.

  * UTCTime, 一个国际协调时（UTC）或者格林威治时间（GMT）.

然后是一些结构

  * SEQUENCE, 一个有序的数据组合，可以包含一个或者多个数据类别.

  * SEQUENCE OF, 一个有序的数据组合，只有一个数据类别，包含零个或者多个数据

  * SET, 一个无序的数据组合，可以包含一个或者多个数据类别

  * SET OF, 一个有序的数据组合，只有一个数据类别，包含零个或者多个数据

  * CHOICE，相当于C/C++中的union

### 3. 公钥矩阵表示 ###
```
//公钥矩阵
CPKPublicParameters ::= SEQUENCE {
        //version 公钥矩阵格式的版本，当前为1
        version                 INTEGER {1}, 
        //表示这个公钥矩阵来源的URI，编码是UTF8
        domainURI               UTF8String,
        //公钥矩阵的相关参数
        publicKeyParameters     PublicKeyDomainParameters,
        //映射函数的OID，(映射函数用来从ID获得一组生成公/私钥的参数)
        mapAlgor                MapAlgorithmIdentifier,
        //公钥矩阵的主要内容，一组椭圆曲线上的点
        publicKeyFactors        OCTET STRING
}

PublicKeyDomainParameters ::= CHOICE {
        //椭圆曲线参数
        ecDomainParameters      ECDomainParameters
}

ECDomainParameters ::= CHOICE {  //CHOICE 相当与 C/C++ 的union
        //ECParameters 结构
        ecParameters            ECParameters, 
        //一个命名曲线的OID
        namedCurve              OBJECT IDENTIFIER,          
        implicitCA              NULL 
}

ECParameters ::= SEQUENCE {
      version         INTEGER { ecpVer1(1) } (ecpVer1),
      fieldID         FieldID {{FieldTypes}},
      //椭圆曲线的描述
      curve           Curve,
      //椭圆曲线的G点
      base            ECPoint,
      //椭圆曲线的阶
      order           INTEGER,
      //椭圆曲线的cofactor，（OPTIONAL=此为可选参数）
      cofactor        INTEGER OPTIONAL
}

Curve ::= SEQUENCE {
      //这里的参数请参考椭圆曲线的定义
      a               FieldElement,
      b               FieldElement,
      seed            BIT STRING      OPTIONAL
}

ECPoint ::= OCTET STRING //椭圆曲线上的点的表示

```

### 4. 私钥矩阵与私钥表示 ###
```
//私钥矩阵
CPKMasterKey ::= SEQUENCE {
        //私钥矩阵格式的版本，当前为1
        version                 INTEGER {1},
        //表示对应公钥矩阵来源的URI，编码是UTF8
        domainURI               UTF8String,
        //参考 3.
        publicKeyParameters     PublicKeyDomainParameters,
        //参考 3.
        mapAlgor                MapAlgorithmIdentifier,
        //私钥矩阵主要内容，一组大整数
        privateKeyFactors       OCTET STRING
}

//私钥
ECPrivateKey ::= SEQUENCE {
        version                 INTEGER { ecPrivkeyVer1(1) },
        privateKey              OCTET STRING,
        parameters [0]          ECDomainParameters OPTIONAL
}

PrivateKeyInfo ::= SEQUENCE {
        version                 INTEGER {0},
        //私钥算法
        privateKeyAlgorithm     AlgorithmIdentifier {{PrivateKeyAlgorithms}},
        //私钥
        privateKey              OCTET STRING {{EncryptedPrivateKeyInfo}},
        //可选属性
        attributes [0]          Attributes OPTIONAL
}

EncryptedPrivateKeyInfo ::= SEQUENCE {
    //对私钥进行加密的算法
    encryptionAlgorithm         EncryptionAlgorithmIdentifier,
    //加密后的私钥
    encryptedData               OCTET STRING 
}

AlgorithmIdentifier ::= SEQUENCE {
    //算法的OID
    algorithm OBJECT IDENTIFIER,
    //算法的参数，可选
    parameters ANY DEFINED BY algorithm OPTIONAL
}

```

### 5. 签名的PKCS#7表示 ###

```
SignedData ::= SEQUENCE { 
	 // SignedData的格式版本
         version                Version, 
         // 对数据进行摘要适应的算法的OID
         digestAlgors           DigestAlgorithmIdentifiers, 
 	 // 根据是否Detached，这里可以选择是否填充原数据
         contentInfo            ContentInfo, 
         // 填充签名者的相关信息
         signerInfos            SignerInfos
}

ContentInfo ::= SEQUENCE { 
         // 内容的类型的OID
         contentType            OJBECT IDENTIFIER,
         // 填充的内容，可选
         content [0]            EXPLICIT ANY DEFINED BY contentType OPTIONAL
}

DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

SignerInfos ::= SET OF SignerInfo

//签名者的信息
SignerInfo ::= SEQUENCE { 
        version                 INTEGER {1}, 
	// 签名者的信息和证书序列号        
        signer                  IssuerAndSerialNumber, 
	// 摘要算法的Identifier
        digestAlgor             DigestAlgorithmIdentifier, 	
        signedAttrs [0]         IMPLICIT Attributes OPTIONAL, 
	// 签名算法的Identifier
        signingAlgor            SigningAlgorithmIdentifier, 
	// 签名的值
        signature               OCTET STRING {{ECDSASigValue}}, 
        unsignedAttrs [1]       IMPLICIT Attributes OPTIONAL
}

IssuerAndSerialNumber ::= SEQUENCE {
     //这里应该是个X509Name，例"CN=alice@bob.com"
     issuer Name,
     //证书序号
     serialNumber CertificateSerialNumber
}
```

### 6. 加密的PKCS#7表示 ###

```
EnvelopedData ::= SEQUENCE { 
        version                 INTEGER {0}, 
	// 接收者的信息
        recipientInfos          RecipientInfos, 
	// 加密的信息
        encedContentInfo        EncryptedContentInfo
}

RecipientInfos ::= SET OF RecipientInfo

EncryptedContentInfo ::= SEQUENCE {
        contentType             ContentType, 
	// 信息的加密算法的Identifier
        contentEncAlgor         EncryptionAlgorithmIdentifier {{id-aes128-CBC}}, 
	// 加密的信息
        encedContent [0]        IMPLICIT OCTET STRING OPTIONAL
}

EncryptionAlgorithmIdentifier ::= AlgoirithmIdentifier

// 接收者的信息
RecipientInfo ::= SEQUENCE {
        version                 INTEGER {0},
	//接收者的X509Name与证书序列号
        recipient               IssuerAndSerialNumber,
	//加密密钥的加密算法的Identifier
        keyEncryptionAlgor      EncryptionAlgorithmIdentifier, 
	//被加密的加密密钥
        encryptedKey            OCTET STRING
}
```

# 三. 参考资料 #
  1. [Abstract Syntax Notation One](http://en.wikipedia.org/wiki/Asn.1) <br>
<ol><li><a href='http://luca.ntop.org/Teaching/Appunti/asn1.html'>A Layman's Guide to a Subset of ASN.1, BER, and DER</a> <br>
</li><li><a href='http://en.wikipedia.org/wiki/Object_identifier'>Object identifier</a> <br>
</li><li><a href='http://www.rsa.com/rsalabs/node.asp?id=2129'>PKCS #7 Cryptographic Message Syntax Standard Version 1.5</a> <br>