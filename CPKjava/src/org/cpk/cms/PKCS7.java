package org.cpk.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSequenceParser;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.cpk.crypto.CPKUtil;
import org.cpk.crypto.MappingAlgorithmException;
import org.cpk.crypto.pubmatrix.PubMatrix;
import org.cpk.crypto.secmatrix.SecMatrix;

/**
 * this class tries to package the encrypt, decrypt, sign, verify data in PKCS#7 standard
 * @author zaexage@gmail.com
 * @see <a href="http://en.wikipedia.org/wiki/PKCS">PKCS</a>
 */
public class PKCS7 {
	
	private Logger logger = Logger.getLogger(PKCS7.class);
	private CPKUtil m_util;
	private SecureRandom m_random;
		
	public PKCS7(CPKUtil util){
		m_util = util;
		m_random = new SecureRandom();
	}
	
	///methods
	/**
	 * sign the raw data and return the PKCS#7 structure encoded in DER, 
	 * @param data the raw data to be signed
	 * @return the PKCS#7 structure encoded in asn.1
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws MappingAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public byte[] Sign(byte[] data, Vector<String> signerIds, Vector<PrivateKey> prikeys, boolean bDetach) throws UnsupportedEncodingException, InvalidKeyException, MappingAlgorithmException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException{
		DERInteger version = new DERInteger(1);
		DERSet algset = new DERSet(OIWObjectIdentifiers.idSHA1);
		ContentInfo contentInfo = null;
		
		if(! bDetach){
			contentInfo = new ContentInfo(PKCSObjectIdentifiers.data, 
					new DEROctetString(data));
		}else{ //if is detached
			contentInfo = new ContentInfo(PKCSObjectIdentifiers.data,
					new DERNull());
		}
		
		ASN1Set certs = null; //certificates, no chance for their presence
		ASN1Set crls = null;  //crls, neither
		
		byte[] elfDigest = CPKUtil.Digest(data, "SHA-1");
//		String dayOfCreation = String.format("%1$tY-%1$tm-%1$te", Calendar.getInstance(TimeZone.getTimeZone("UTC")));
		ASN1EncodableVector attrs = new ASN1EncodableVector();
		attrs.add(new DEROctetString(elfDigest));
		attrs.add(new Time(new Date()));
		SignerInfo[] signerInfosArr = new SignerInfo[signerIds.size()];	
		
		for(int i=0; i<signerIds.size(); ++i){
			String id = signerIds.get(i);
			SignerInfo info = new SignerInfo(		
					version,
					new IssuerAndSerialNumber(new X509Name("CN="+id), new DERInteger(1)), 
					new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), 
					new DERSet(attrs),
					new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA1),
					new DEROctetString(CPKUtil.Sign(data, prikeys.get(i))),
					null);
			signerInfosArr[i] = info;
		}
		DERSet signerInfos = new DERSet(signerInfosArr);
		
		SignedData signedData = new SignedData(version, algset, contentInfo, certs, crls, signerInfos);
		
		byte[] ret = signedData.getDEREncoded();
		if( null == ret ){
			throw new UnsupportedEncodingException("PKCS7.Sign: encode DER failed");
		}
		
		return ret;
	}	
	
	/**
	 * this method will verify the whether signature in PKCS#7 package is valid
	 * @param pkcs7data the pkcs#7 packaged data
	 * @param detachedData if original data is detached then set it here, or set it null
	 * @return whether the signature is valid
	 * @throws IOException 
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws MappingAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public boolean Verify(byte[] pkcs7data, byte[] detachedData) throws IOException, InvalidKeyException, MappingAlgorithmException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException{
		ASN1Sequence seq = (ASN1Sequence)DERSequence.fromByteArray(pkcs7data);
		SignedData signedData = SignedData.getInstance(seq);
		byte[] oridata = detachedData;
		
		assert(signedData.getVersion().getValue().intValue() == 1); //assert version is 1
		
		if(oridata == null){ //means the original data is attached
			ContentInfo contentInfo = signedData.getContentInfo();
			oridata = ((DEROctetString)contentInfo.getContent()).getOctets();
		}
		
		ASN1Set signerInfos = signedData.getSignerInfos();
		Enumeration<ASN1Sequence> e = signerInfos.getObjects();
		while(e.hasMoreElements()){
			ASN1Sequence siseq = e.nextElement();
			SignerInfo si = new SignerInfo(siseq);
			
			IssuerAndSerialNumber iasn = si.getIssuerAndSerialNumber();
			X509Name name = iasn.getName();
			String id = (String)name.getValues(X509Name.CN).get(0); //get the signer id
			
			byte[] sig = si.getEncryptedDigest().getOctets();
			boolean bValid = m_util.Verify(oridata, sig, id);
			if(! bValid ){
				logger.info("for userid:"+id+" , the signature is invalid:" + new String(Hex.encode(sig)));
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * encrypt given data, package the cipher text according to PKCS#7 standard.
	 * first generate a session key(AES/CBC) for encrypting message, 
	 * use ECIES algorithm, id-generated public key, and given private key, to encrypt the session key,
	 * later, use the session key to encrypt the original data;
	 * encode the whole lot with DER encoding and return  
	 * @param data the original data
	 * @param priKey the sender's private key
	 * @param receivers the receivers' ids, by which to generate public keys
	 * @return the encrypted byte[]
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 * @throws MappingAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws InvalidParameterSpecException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public byte[] Encrypt(byte[] data, PrivateKey priKey, String senderId, Vector<String> receivers) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, MappingAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidParameterSpecException, InvalidAlgorithmParameterException{
		///create recipientInfos
		DEREncodableVector recipientInfosVec = new DEREncodableVector();
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		gen.init(m_random);
		SecretKey cipherkey = gen.generateKey(); //session key
		for(int i=0; i<receivers.size(); ++i){
			org.bouncycastle.asn1.cms.IssuerAndSerialNumber iasn = 
				new org.bouncycastle.asn1.cms.IssuerAndSerialNumber(
					new X509Name("CN="+receivers.get(i)), 
					new DERInteger(1)
				);
			ByteArrayOutputStream algParamStream = new ByteArrayOutputStream();
			byte[] encedCipherKey = m_util.Encrypt(cipherkey.getEncoded(),
					priKey, receivers.get(i),
					algParamStream); //session key is encrypted with receiver's public key with ECIES alg
			System.out.println("PKCS7.Encrypt: encedCipherKey : "+new String(Hex.encode(encedCipherKey)));
			RecipientIdentifier recIdentifier = new RecipientIdentifier(iasn);	
			DEREncodableVector algParameters = new DEREncodableVector();
			algParameters.add(new DEROctetString(algParamStream.toByteArray()));
			algParameters.add(new DEROctetString(senderId.getBytes("UTF-8")));			
			System.out.println("here: algParam is  :"+new String(Hex.encode(new DEROctetString(algParamStream.toByteArray()).getOctets())));
			AlgorithmIdentifier algIdentifier = new AlgorithmIdentifier(CPKUtil.ECIES, new DERSequence(algParameters));
			RecipientInfo recipientInfo = new RecipientInfo(
				new KeyTransRecipientInfo(recIdentifier, algIdentifier, new DEROctetString(encedCipherKey)));
			byte[] ooo = ((KeyTransRecipientInfo)recipientInfo.getInfo()).getEncryptedKey().getOctets();
			recipientInfosVec.add(recipientInfo);
		}
		ASN1Set recipientInfos = new DERSet(recipientInfosVec); //recipient info construction done
		
		Cipher cipherAlg = Cipher.getInstance("AES"); //encrypt the original data
		cipherAlg.init(Cipher.ENCRYPT_MODE, cipherkey);
		byte[] output = cipherAlg.doFinal(data);
		DEROctetString octetStr = new DEROctetString(output);
		EncryptedContentInfo encContentInfo = new EncryptedContentInfo(
				CMSObjectIdentifiers.encryptedData,
				new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_CBC),
				octetStr
		);
		
		EnvelopedData envData = new EnvelopedData(null, recipientInfos, encContentInfo, null);
		
		return envData.getDEREncoded();
	}
	
	/**
	 * decrypt enveloped data, need decrypter's id and private key
	 * @param envDataBytes data to be decrypted, enveloped in PKCS#7 standard format
	 * @param recverid decrypter's id
	 * @param recverPrikey decrypter's private key
	 * @return the clear text
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 * @throws MappingAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchProviderException
	 * @throws InvalidParameterSpecException
	 */
	public byte[] Decrypt(byte[] envDataBytes, String recverid, PrivateKey recverPrikey) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, MappingAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidParameterSpecException{
		ASN1Sequence seq = (ASN1Sequence)DERSequence.fromByteArray(envDataBytes);
		EnvelopedData envData = EnvelopedData.getInstance(seq);
		ASN1Set recipientInfos = envData.getRecipientInfos();
		for(int i=0; i<recipientInfos.size(); ++i){
			RecipientInfo info = RecipientInfo.getInstance(recipientInfos.getObjectAt(i));
			KeyTransRecipientInfo keyinfo = (KeyTransRecipientInfo)info.getInfo();
			RecipientIdentifier identifier = keyinfo.getRecipientIdentifier();
			org.bouncycastle.asn1.cms.IssuerAndSerialNumber iasn = 
				(org.bouncycastle.asn1.cms.IssuerAndSerialNumber)identifier.getId();
			X509Name name = iasn.getName();
			String intendedRecverId = (String) name.getValues(X509Name.CN).get(0);
			if(intendedRecverId.equals(recverid)){ //this is the id recverPriKey corresponding to
				byte[] encedCipherKey = keyinfo.getEncryptedKey().getOctets();
				System.out.println("PKCS7.Decrypt: encedCipherKey : " + new String(Hex.encode(encedCipherKey)));
				ASN1Sequence parameters = DERSequence.getInstance(keyinfo.getKeyEncryptionAlgorithm().getParameters());
				String senderId = new String(((DEROctetString)parameters.getObjectAt(1)).getOctets(), "UTF-8");
				AlgorithmParameters algParam = AlgorithmParameters.getInstance("IES");
				CPKUtil.InitAlgParam(((DEROctetString)parameters.getObjectAt(0)).getOctets(), algParam);
				byte[] cipherKeyEncoded = m_util.Decrypt(encedCipherKey, recverPrikey, senderId, algParam); //the session key decrypted
				SecretKeySpec cipherKey = new SecretKeySpec(cipherKeyEncoded, "AES");
//				SecretKeyFactory skFactory = SecretKeyFactory.getInstance("AES");
//				SecretKey cipherKey = skFactory.generateSecret(keyspec);
				
				EncryptedContentInfo encInfo = envData.getEncryptedContentInfo();
				byte[] encedData = encInfo.getEncryptedContent().getOctets();
				Cipher cipher = Cipher.getInstance("AES");
				cipher.init(Cipher.DECRYPT_MODE, cipherKey);
				System.out.println("cipherText before decrypt: "+new String(Hex.encode(encedData)));
				byte[] clearText = cipher.doFinal(encedData);
				
				return clearText;
			}
		}
		//if no intendedRecvId meets given 'recverid' then return null
		return null;
	}	
}
