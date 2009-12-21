package org.cpk.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.cpk.crypto.pubmatrix.PubMatrix;
import org.cpk.crypto.pubmatrix.PubMatrixSerializer;
import org.cpk.crypto.secmatrix.SecMatrix;
import org.cpk.crypto.secmatrix.SecMatrixSerializer;

import org.apache.log4j.Logger;

/**
 * this class provides several helper functions including, sign, verify, encrypt, decrypt.
 * on the raw data (without PKCS7) 
 * @author zaexage@gmail.com
 */
public class CPKUtil {

	public static final DERObjectIdentifier ECIES = new DERObjectIdentifier("1.0.18033.2.2.1");
	private static Logger logger = Logger.getLogger(CPKUtil.class);
	
	private SecMatrix m_secmatrix;
	private PubMatrix m_pubmatrix;
	
	/**
	 * initialize the CPKUtil instance with given {@link org.cpk.crypto.secmatrix.SecMatrix secret matrix} or {@link org.cpk.crypto.pubmatrix.PubMatrix public matrix}
	 * @param secmatrix [optional] the secret matrix used to derive private key from id
	 * @param pubmatrix the public matrix used to derive public key from id 
	 */
	public CPKUtil(SecMatrix secmatrix, PubMatrix pubmatrix){
		this.m_secmatrix = secmatrix;
		this.m_pubmatrix = pubmatrix;
	}
	
	/**
	 * will use two importers to import matrices
	 * @param secImport if not available, set it null
	 * @param pubImport PubMatrixSerializer instance
	 * @throws IOException 
	 */
	public CPKUtil(SecMatrixSerializer secImport, PubMatrixSerializer pubImport) throws IOException{
		if(secImport != null)
			m_secmatrix = secImport.GetSecMatrix();
		if(pubImport != null)
			m_pubmatrix = pubImport.GetPubMatrix();
	}
	
	/**
	 * this method will sign the given original data based on the secret matrix and signerId;
	 * need `secret matrix' to be set at CPKUtil initialization 
	 * @param data a small amount of data, e.g.: the digest of a bunch of data
	 * @param signerId the id of the entity who signed the data
	 * @return raw signature(without PKCS#7 package)
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public byte[] Sign(byte[] data, String signerId)
		throws MappingAlgorithmException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		assert(m_secmatrix != null);
		PrivateKey priKey = m_secmatrix.GeneratePrivateKey(signerId);
		Signature sigAlg = Signature.getInstance("ECDSA");
				
		sigAlg.initSign(priKey);
		sigAlg.update(data);
		byte[] sig = sigAlg.sign();		
		
		return sig;
	}
	
	/**
	 * this method will sign the given original data with the given PrivateKey
	 * @param data a small amount of data, e.g.: the digest of a bunch of data
	 * @param prikey the private key of signer
	 * @return raw signature(without PKCS#7 package)
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 */
	public static byte[] Sign(byte[] data, PrivateKey prikey)
		throws NoSuchAlgorithmException, SignatureException, InvalidKeyException{
		
		Signature sigAlg = Signature.getInstance("ECDSA");
		sigAlg.initSign(prikey);
		sigAlg.update(data);
		byte[] sig = sigAlg.sign();
		
		return sig;
	}
	
	/**
	 * given the original data, signature, and signer's ID, judge the signature's validity
	 * need `public matrix' to be set at CPKUtil initialization 
	 * @param data the original data, e.g.: the digest
	 * @param sig the signature to be verified 
	 * @param signerId the id of the signer
	 * @return iff the signature is good, return true
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public boolean Verify(byte[] data, byte[] sig, String signerId) 
		throws MappingAlgorithmException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		PublicKey pubKey = m_pubmatrix.GeneratePublicKey(signerId);
		Signature sigAlg = Signature.getInstance("ECDSA");
		
		sigAlg.initVerify(pubKey);
		sigAlg.update(data);
		return sigAlg.verify(sig);
	}
		
	/**
	 * encrypt the given data with ECIES algorithm, the encrypting key is generated with 
	 * Alice's PrivateKey and Bob's Id
	 * [WARNING: this function only applies to small amount of data, huge data will cause heap overflow] 
	 * @param data the original data
	 * @param AliceKey the encrypter's PrivateKey
	 * @param BobId the decrypter's id
	 * @param param [OPTIONAL, inout] contains the encoded AlgorithmParameter
	 * @return encrypted data
	 * @throws MappingAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidParameterSpecException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public byte[] Encrypt(byte[] data, PrivateKey AliceKey, String BobId, ByteArrayOutputStream param) throws InvalidKeySpecException, MappingAlgorithmException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, InvalidAlgorithmParameterException{
		Cipher cipher = encrypt_pub(AliceKey, BobId, param);
		byte[] cipherText = cipher.doFinal(data);
		
		System.out.println("Encrypt: cipherText: " + new String(Hex.encode(cipherText)));
		return cipherText;
	}

	
	/**
	 * encrypt the data from InputStream and return the encrypted byte[] 
	 * [WARNING: this function only applies to small amount of data, huge data will cause heap overflow]
	 * @param is input stream
	 * @param AliceKey encrypter's private key
	 * @param BobId decrypter's id
	 * @param param [OPTIONAL][inout] encryption algorithm parameter
	 * @return encrypted data
	 * @throws MappingAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] Encrypt(InputStream is, PrivateKey AliceKey, String BobId, ByteArrayOutputStream param) throws InvalidKeySpecException, MappingAlgorithmException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException{
		Cipher cipher = encrypt_pub(AliceKey, BobId, param);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		byte[] buf = new byte[4096];
		
		CipherInputStream cis = new CipherInputStream(is, cipher);
		while(true){
			int len = cis.read(buf);
			if( -1 == len ){ //eof				
				break;
			}
			bos.write(buf, 0, len);
		}
		
		return bos.toByteArray();
	}
	
	/**
	 * encrypt the data from given InputStream, and output:<br>
	 * 1) ECIES algorithm parameters and encrypted symmetry session key to output stream <br>
	 * 2) the cipher text to given OutputStream<br>
	 * [NOTE: this function could handle huge amount of data]
	 * @param is stream where data comes from
	 * @param os stream where result goes to
	 * @param AliceKey encrypter's private key
	 * @param BobId the decrypter's id, used to generate public key for encryption	 
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IOException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public void Encrypt(InputStream is, 
			OutputStream os,
			PrivateKey AliceKey, 
			String BobId			
			) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException{
		Cipher cipher = encrypt_pub(AliceKey, BobId, null); //the ECIES cipher used to encrypt session key
				
		//generate session key
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		gen.init(128, new SecureRandom());
		SecretKey sessionKey = gen.generateKey();		
		byte[] encryptedSessionKey = cipher.doFinal(sessionKey.getEncoded());

		//output encrypted session key to output stream
		ASN1EncodableVector seq = new ASN1EncodableVector();
		seq.add(new DEROctetString(cipher.getParameters().getEncoded()));
		seq.add(new DEROctetString(encryptedSessionKey));		
		os.write(new DERSequence(seq).getDEREncoded());
		
		//use session key to encrypt clear text and output to output stream
		byte[] buf = new byte[4096];
		Cipher sessionCipher = Cipher.getInstance("AES");
		sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey);		
		
		CipherInputStream cis = new CipherInputStream(is, sessionCipher);		
		while(true){
			int len = cis.read(buf);
			if( -1 == len ){				
				break;
			}
			os.write(buf, 0, len);
		}		
	}
	
	/**
	 * Decrypt the given cipherData, with the decrypter(Bob)'s private key and
	 * encrypter(Alice)'s id
	 * @param cipherData the cipher text
	 * @param BobKey the decrypter's private key
	 * @param AliceId the encrypter's id
	 * @return the clear text
	 * @throws MappingAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] Decrypt(byte[] cipherData, PrivateKey BobKey, String AliceId, AlgorithmParameters param) throws InvalidKeySpecException, MappingAlgorithmException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
//		System.out.println("Decrypt: cipherData: "+new String(Hex.encode(cipherData)));
//		System.out.println("Decrypt: SenderId: " + AliceId);
		Cipher cipher = decrypt_pub(BobKey, AliceId, param);
		
		byte[] clearText = cipher.doFinal(cipherData);
		return clearText;
	}
	
	/**
	 * decrypt data from given InputStream, output the decrypted data in byte[]
	 * @param is the InputStream where the cipher text comes
	 * @param BobKey the decrypter's private key
	 * @param AliceId the encrypter's id
	 * @param param the algorithm's parameters
	 * @return the clear data in byte[]
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IOException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] Decrypt(InputStream is, PrivateKey BobKey, String AliceId, AlgorithmParameters param) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException{
		Cipher cipher = decrypt_pub(BobKey, AliceId, param);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		byte[] buf = new byte[4096];
		
		CipherInputStream cis = new CipherInputStream(is, cipher);
		while(true){
			int len = cis.read(buf);
			if( -1 == len ){ //eof				
				break;
			}
			bos.write(buf, 0, len);
		}
		
		return bos.toByteArray();
	}
	
	/**
	 * first extract encrypted session key and ECIES algorithm parameters from head of input stream, then 
	 * decrypt the data from given InputStream with session key, output the decrypted data to given OutputStream
	 * @param is the InputStram where encrypted data comes from
	 * @param os the OutputStream where decrypted data goes to
	 * @param BobKey the decrypter's PrivateKey
	 * @param AliceId the encrypter's ID	 	 
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IOException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidParameterSpecException 
	 */
	public void Decrypt(InputStream is, 
			OutputStream os, 
			PrivateKey BobKey, 
			String AliceId			
			)
	throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException{
				
		ASN1InputStream asn1is = new ASN1InputStream(is);
		DERSequence seq = (DERSequence)asn1is.readObject();
		byte[] encodedParam = ((DEROctetString)seq.getObjectAt(0)).getOctets();
		AlgorithmParameters param = AlgorithmParameters.getInstance("IES");
		InitAlgParam(encodedParam, param);
		byte[] EncryptEncodededSessionKey = ((DEROctetString)seq.getObjectAt(1)).getOctets();
				
		Cipher iesCipher = decrypt_pub(BobKey, AliceId, param); //the cipher used to decrypt symmetric key
		byte[] EncodedSessionKey = iesCipher.doFinal(EncryptEncodededSessionKey); //the symmetric session key 
		
		SecretKeySpec cipherKey = new SecretKeySpec(EncodedSessionKey, "AES"); //decode from binary format to secret key 
		Cipher sessionCipher = Cipher.getInstance("AES");		
		sessionCipher.init(Cipher.DECRYPT_MODE, cipherKey);
		
		byte[] buf = new byte[4096];
		CipherInputStream cis = new CipherInputStream(asn1is, sessionCipher);
		while(true){
			int len = cis.read(buf);
			if( -1 == len ){				
				break; //eof
			}
			os.write(buf, 0, len);			
		}	
	}

//	private AlgorithmParameters extractAlgParameterFromInputStreamHead(
//			InputStream is) throws IOException, NoSuchAlgorithmException,
//			InvalidParameterSpecException {
//		AlgorithmParameters param;
//		byte[] tmpbuf = new byte[256];
//		is.read(tmpbuf, 0, 2);
//		is.read(tmpbuf, 2, tmpbuf[1]);
//		byte[] encodedAlgParam = ByteBuffer.wrap(tmpbuf, 0, tmpbuf[1]+2).array();
//		param = AlgorithmParameters.getInstance("IES");
//		InitAlgParam(encodedAlgParam, param);
//		return param;
//	}
	
	/**
	 * Digest given data with specified algorithm, return the digest.
	 * @param data the original data
	 * @param alg the message digest algorithm's name
	 * @return the produced digest
	 * @throws NoSuchAlgorithmException 
	 */
	static public byte[] Digest(byte[] data, String alg) throws NoSuchAlgorithmException{
		MessageDigest dgstAlg = MessageDigest.getInstance(alg);
		return dgstAlg.digest(data);		
	}
	
	/**
	 * generate a group of private keys according to a group of ids
	 * @param ids a vector of id
	 * @param secmatrix the secret matrix
	 * @return a vector filled with corresponding PrivateKey
	 * @throws InvalidKeySpecException
	 * @throws MappingAlgorithmException
	 */
	static public Vector<PrivateKey> GeneratePrivateKeyFromId(Vector<String> ids, SecMatrix secmatrix) throws InvalidKeySpecException, MappingAlgorithmException{
		Vector<PrivateKey> keys = new Vector<PrivateKey>(ids.size());
		for(int i=0; i<ids.size(); ++i){
			keys.add(secmatrix.GeneratePrivateKey(ids.get(i)));
		}
		return keys;
	}
	
	/**
	 * init the AlgorithmParameters from previously encoded byte[]
	 * @param parameters the encoded parameters
	 * @param algParam the instance to be initialized with the encoded byte[]
	 * @throws IOException
	 * @throws InvalidParameterSpecException
	 */
	public static void InitAlgParam(byte[] parameters,
			AlgorithmParameters algParam) throws IOException, InvalidParameterSpecException {
		ASN1Sequence inAlgParam = (ASN1Sequence) DERSequence.fromByteArray(parameters);
		byte[] p1 = ((DEROctetString)inAlgParam.getObjectAt(0)).getOctets();
		byte[] p2 = ((DEROctetString)inAlgParam.getObjectAt(1)).getOctets();
		int p3 = ((DERInteger)inAlgParam.getObjectAt(2)).getValue().intValue();
		IESParameterSpec spec = new IESParameterSpec(p1, p2, p3);
//		System.out.println("p1:" + new String(Hex.encode(p1)));
//		System.out.println("p2:" + new String(Hex.encode(p2)));
//		System.out.println("p3:" + String.valueOf(p3));
		algParam.init(spec);
	}
	
	/**
	 * this private function extracts some common parts for all versions of Encrypt()
	 * @param AliceKey encrypter's private key
	 * @param BobId decrypter's id
	 * @param param [inout, OPTIONAL] algorithm parameter
	 * @return prepared Cipher instance
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IOException
	 */
	private Cipher encrypt_pub(PrivateKey AliceKey, String BobId,
			ByteArrayOutputStream param) throws InvalidKeySpecException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IOException {
		PublicKey pubkey = m_pubmatrix.GeneratePublicKey(BobId);
		Cipher cipher = Cipher.getInstance("ECIES");
//		IESParameterSpec paramSpec = new IESParameterSpec(
//				new byte[]{1,2,3,4,5,6,7,8},
//				new byte[]{8,7,6,5,4,3,2,1},
//				128
//			);
		IEKeySpec spec = new IEKeySpec(AliceKey, pubkey);
		cipher.init(Cipher.ENCRYPT_MODE, spec);
		if(param != null){
			AlgorithmParameters parameters = cipher.getParameters();			
			byte[] outparam = parameters.getEncoded();
			System.out.println("the algparameter is:" + new String(Hex.encode(outparam)));
			param.write(outparam);
			
//			AlgorithmParameterSpec algspec = new IESParameterSpec(null, null, 0);
//			IESParameterSpec algspec = parameters.getParameterSpec(IESParameterSpec.class);
//			System.out.println("Encrypt: p1: "+new String(Hex.encode(algspec.getDerivationV())));
//			System.out.println("Encyrpt: p2: "+new String(Hex.encode(algspec.getEncodingV())));
//			System.out.println("Encrypt: p3: "+String.valueOf(algspec.getMacKeySize()));
		}
		return cipher;
	}
	
	/**
	 * some common code for all versions of Decrypt()
	 * @param BobKey the decrypter's private key
	 * @param AliceId the encrypter's ID
	 * @param param the AlgorithmParameter to initialize Cipher
	 * @return prepared Cipher instance
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	private Cipher decrypt_pub(PrivateKey BobKey, String AliceId,
			AlgorithmParameters param) throws InvalidKeySpecException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		PublicKey pubkey = m_pubmatrix.GeneratePublicKey(AliceId);
		Cipher cipher = Cipher.getInstance("ECIES");
//		IESParameterSpec paramSpec = new IESParameterSpec(
//				new byte[]{1,2,3,4,5,6,7,8},
//				new byte[]{8,7,6,5,4,3,2,1},
//				128
//			);
		IEKeySpec spec = new IEKeySpec(BobKey, pubkey);
		cipher.init(Cipher.DECRYPT_MODE, spec, param);
		return cipher;
	}

}
