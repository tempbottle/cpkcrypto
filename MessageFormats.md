# summary One-sentence summary of this page.


```



-- DigestAlgorithmIdentifier Values--
sha-1 OBJECT IDENTIFIER ::= {iso(1) identified-organization(3) oiw(14) 
	secsig(3) algorithm(2) 26}
id-sha224 OBJECT IDENTIFIER ::= { id-sha 4 } 
id-sha256 OBJECT IDENTIFIER ::= { id-sha 1 } 
id-sha384 OBJECT IDENTIFIER ::= { id-sha 2 }
id-sha512 OBJECT IDENTIFIER ::= { id-sha 3 }



-- AES information object identifiers --
aes OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
	organization(1) gov(101) csor(3)_ nistAlgorithms(4)  1 }
-- AES using CBC-chaining mode for key sizes of 128, 192, 256
id-aes128-CBC OBJECT IDENTIFIER ::= { aes 2 }
id-aes192-CBC OBJECT IDENTIFIER ::= { aes 22 }
id-aes256-CBC OBJECT IDENTIFIER ::= { aes 42 }
-- AES-IV is a the parameter for all the above object identifiers.
AES-IV ::= OCTET STRING (SIZE(16))
-- AES Key Wrap Algorithm Identifiers  - Parameter is absent
id-aes128-wrap OBJECT IDENTIFIER ::= { aes 5 }
id-aes192-wrap OBJECT IDENTIFIER ::= { aes 25 }
id-aes256-wrap OBJECT IDENTIFIER ::= { aes 45 }




x9-63-scheme OBJECT IDENTIFIER ::= { iso(1)
         identified-organization(3) tc68(133) country(16) x9(840)
         x9-63(63) schemes(0) }


ecdsa-with-SHA256  OBJECT IDENTIFIER  ::=  { iso(1) member-body(2)
          us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-sha2(3) 2 }


CPKPublicParameters ::= SEQUENCE {
	version			INTEGER {1},
	domainURI		UTF8String,
	publicKeyParameters	PublicKeyDomainParameters,
	mapAlgor		MapAlgorithmIdentifier,
	publicKeyFactors	OCTET STRING
}

PublicKeyDomainParameters ::= CHOICE {
	ecDomainParameters	ECDomainParameters
}

ECDomainParameters ::= CHOICE { 
	ecParameters		ECParameters, 
	namedCurve		OBJECT IDENTIFIER, 
	implicitCA		NULL 
}

CPKMasterKey ::= SEQUENCE {
	version			INTEGER {1},
	domainURI		UTF8String,
	publicKeyParameters	PublicKeyDomainParameters,
	mapAlgor		MapAlgorithmIdentifier,
	privateKeyFactors	OCTET STRING
}

ECPrivateKey ::= SEQUENCE {
	version			INTEGER { ecPrivkeyVer1(1) },
	privateKey		OCTET STRING,
	parameters [0]		ECDomainParameters OPTIONAL
}

PrivateKeyInfo ::= SEQUENCE {
	version			INTEGER {0},
	privateKeyAlgorithm	AlgorithmIdentifier {{PrivateKeyAlgorithms}},
	privateKey		OCTET STRING {{EncryptedPrivateKeyInfo}},
	attributes [0]		Attributes OPTIONAL
}

EncryptedPrivateKeyInfo ::= SEQUENCE {
    encryptionAlgorithm		EncryptionAlgorithmIdentifier,
    encryptedData		OCTET STRING 
}

ContentInfo ::= SEQUENCE { 
	 contentType		OJBECT IDENTIFIER,
	 content [0]		EXPLICIT ANY DEFINED BY contentType OPTIONAL
}

pkcs-7 OBJECT IDENTIFIER ::= { iso(1) member-body(2) US(840) rsadsi(113549) pkcs(1) 7 }
data OBJECT IDENTIFIER ::= { pkcs-7 1 }
signedData OBJECT IDENTIFIER ::= { pkcs-7 2 }
envelopedData OBJECT IDENTIFIER ::= { pkcs-7 3 }
signedAndEnvelopedData OBJECT IDENTIFIER ::= { pkcs-7 4 }
digestedData OBJECT IDENTIFIER ::= { pkcs-7 5 }
encryptedData OBJECT IDENTIFIER ::= { pkcs-7 6 }

Data ::= OCTET STRING

SignedData ::= SEQUENCE { 
	 version		Version, 
	 digestAlgors		DigestAlgorithmIdentifiers, 
	 contentInfo		ContentInfo, 
	 signerInfos		SignerInfos
}

DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

SignerInfos ::= SET OF SignerInfo

SignerInfo ::= SEQUENCE { 
	version			INTEGER {1}, 
	signer			IssuerAndSerialNumber, 
	digestAlgor		DigestAlgorithmIdentifier, 
	signedAttrs [0]		IMPLICIT Attributes OPTIONAL, 
	signingAlgor		SigningAlgorithmIdentifier, 
	signature		OCTET STRING {{ECDSASigValue}}, 
	unsignedAttrs [1]	IMPLICIT Attributes OPTIONAL
}

-- SigningAlgorithmIdentifier Values --
ecdsa-with-SHA1 OBJECT IDENTIFIER ::= { id-ecSigType sha1(1)} 
ecdsa-with-Recommended OBJECT IDENTIFIER ::= { id-ecSigType recommended(2) } 
ecdsa-with-Specified OBJECT IDENTIFIER ::= { id-ecSigType specified(3)} 
ecdsa-with-Sha224 OBJECT IDENTIFIER ::= { id-ecSigType specified(3) 1 } 
ecdsa-with-Sha256 OBJECT IDENTIFIER ::= { id-ecSigType specified(3) 2 } 
ecdsa-with-Sha384 OBJECT IDENTIFIER ::= { id-ecSigType specified(3) 3 } 
ecdsa-with-Sha512 OBJECT IDENTIFIER ::= { id-ecSigType specified(3) 4 }

ECDSASigValue ::= SEQUENCE {
	r			INTEGER,
	s			INTEGER
}

DigestInfo ::= SEQUENCE { 
	digestAlgor		DigestAlgorithmIdentifier, 
	digest			OCTET STRING
}

EnvelopedData ::= SEQUENCE { 
	version			INTEGER {0}, 
	recipientInfos		RecipientInfos, 
	encedContentInfo	EncryptedContentInfo
}

RecipientInfos ::= SET OF RecipientInfo

EncryptedContentInfo ::= SEQUENCE {
	contentType		ContentType, 
	contentEncAlgor		EncryptionAlgorithmIdentifier {{id-aes128-CBC}}, 
	encedContent [0]	IMPLICIT OCTET STRING OPTIONAL
}

EncryptionAlgorithmIdentifier ::= AlgoirithmIdentifier

RecipientInfo ::= SEQUENCE {
	version			INTEGER {0},
	recipient		IssuerAndSerialNumber,
	keyEncryptionAlgor	EncryptionAlgorithmIdentifier, 
	encryptedKey		OCTET STRING
}

ECIESAlgorithmSet ALGORITHM ::= {
	{OID ecies-recommendedParameters} | 
	{OID ecies-specifiedParameters PARMS ECIESParameters}
}

ecies-recommendedParameters OBJECT IDENTIFIER ::= {secg-scheme 7} 
ecies-specifiedParameters OBJECT IDENTIFIER ::= {secg-scheme 8} 

ECIESParameters ::= SEQUENCE { 
	kdf [0]			KeyDerivationFunction OPTIONAL, 
	sym [1]			SymmetricEncryption OPTIONAL, 
	mac [2]			MessageAuthenticationCode OPTIONAL 
}

KeyDerivationFunction ::= AlgorithmIdentifier {
	{ OID x9-63-kdf PARMS HashAlgorithm }
}

x9-63-kdf OBJECT IDENTIFIER ::= {secg-scheme 17 0}

SymmetricEncryption ::= AlgorithmIdentifier {
	{ OID aes128-cbc-in-ecies } |
	{ OID aes128-ctr-in-ecies }
}

MessageAuthenticationCode ::= AlgorithmIdentifier {
	{ OID hmac-full-ecies PARMS HashAlgorithm }
}  

ECIES-Ciphertext-Value ::= SEQUENCE {
	ephemeralPublicKey	ECPoint,
	symmetricCiphertext	OCTET STRING {{EncryptedData}}, 
	macTag			OCTET STRING 
}

ECPoint ::= OCTET STRING

SignedAndEnvelopedData ::= SEQUENCE { 
	version			INTEGER {1}, 
	recipientInfos		RecipientInfos, 
	digestAlgors		DigestAlgorithmIdentifiers, 
	encedContentInfo	EncryptedContentInfo,
	signerInfos		SignerInfos
}

DigestedData ::= SEQUENCE { 
	version			INTEGER {0}, 
	digestAlgor		DigestAlgorithmIdentifier, 
	contentInfo		ContentInfo, 
	digest			OCTET STRING
} 





```

```
AlgorithmIdentifier{ ALGORITHM:IOSet } ::= SEQUENCE {
    algorithm ALGORIHTM.\&id({IOSet}),
    parameters ALGORITHM.\&Type({IOSet}{\@algorithm})
}
```


### 参考文献 ###

  1. [SEC 1: Elliptic Curve Crytography (working draft v 1.9)](http://www.secg.org/download/aid-773/sec1_1point9.pdf)
  1. [PKCS #7 Cryptographic Message Syntax Standard Version 1.5](http://www.rsa.com/rsalabs/node.asp?id=2129)
  1. [RFC 3852 - Cryptographic Message Syntax (CMS)](http://www.faqs.org/rfcs/rfc3852.html)
  1. [RFC 2985 - PKCS #9: Selected Object Classes and Attribute Types](http://www.faqs.org/rfcs/rfc2985.html)
  1. [RFC 3565 Use of the Advanced Encryption Standard (AES) Encryption Algorithm in Cryptographic Message Syntax (CMS)](http://www.faqs.org/rfcs/rfc3565.html)
  1. [RFC 3278 Use of Elliptic Curve Cryptography (ECC) Algorithms in Cryptographic Message Syntax (CMS)](http://rfc.giga.net.tw/rfc3278)