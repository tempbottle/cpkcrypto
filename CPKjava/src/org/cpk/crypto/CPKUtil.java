package org.cpk.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
 * this class provides several helpers including, sign, verify, encrypt, decrypt.
 * on the raw data(without PKCS7) 
 * @author ZaeX
 */
public class CPKUtil {

	public static final DERObjectIdentifier ECIES = new DERObjectIdentifier("1.0.18033.2.2.1");
	private Logger logger = Logger.getLogger(CPKUtil.class);
	
	private SecMatrix m_secmatrix;
	private PubMatrix m_pubmatrix;
	
	/**
	 * just use the two initialized matrices to fill the CPKUtil class
	 * @param secmatrix already inited instance, if not available, set it null
	 * @param pubmatrix already inited instance
	 */
	public CPKUtil(SecMatrix secmatrix, PubMatrix pubmatrix){
		this.m_secmatrix = secmatrix;
		this.m_pubmatrix = pubmatrix;
	}
	
	/**
	 * will use two importers to import matrices
	 * @param secImport if not available, set it null
	 * @param pubImport
	 * @throws IOException 
	 */
	public CPKUtil(SecMatrixSerializer secImport, PubMatrixSerializer pubImport) throws IOException{
		m_secmatrix = secImport.GetSecMatrix();
		m_pubmatrix = pubImport.GetPubMatrix();
	}
	
	/**
	 * this method will sign the given original data based on the m_secmatrix and 
	 * signerId
	 * @param data
	 * @param signerId
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
	 * @param data
	 * @param prikey
	 * @return raw signature(without PKCS#7 package)
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 */
	public byte[] Sign(byte[] data, PrivateKey prikey)
		throws NoSuchAlgorithmException, SignatureException, InvalidKeyException{
		
		Signature sigAlg = Signature.getInstance("ECDSA");
		sigAlg.initSign(prikey);
		sigAlg.update(data);
		byte[] sig = sigAlg.sign();
		
		return sig;
	}
	
	/**
	 * given the original data, signature, and signer's ID, judge the 
	 * signature's validity
	 * @param data
	 * @param signerId
	 * @return
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
	 * Alice's PrivateKey and Bob's Id, if param is given, the algorithm parameter is returned by that 
	 * @param data the original data
	 * @param AliceId the encrypter's PrivateKey
	 * @param BobId the receiver's id
	 * @param param [OPTIONAL] contains the encoded AlgorithmParameter
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
	 * @param is input stream
	 * @param AliceKey private key used to encrypt
	 * @param BobId recver's id
	 * @param param [OPTIONAL][in,out] encryption algorithm
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
			int len = is.read(buf);
			if( -1 == len ){ //eof
				break;
			}
			bos.write(buf, 0, len);
		}
		
		return bos.toByteArray();
	}
	
	/**
	 * encrypt the data from given InputStream, and output the result to given OutputStream
	 * @param is stream where data comes from
	 * @param os stream where result goes to
	 * @param AliceKey the private key used to encrypt
	 * @param BobId the recver's id, used to generate public key for encryption
	 * @param param [OPTIONAL][in,out] the ByteArrayOutputStream to contains the Cipher's parameters
	 * @param bEncodeParam if true, will encode and output AlgorithmParameter to the {@code os} first, then the encrypted data
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
			String BobId,
			ByteArrayOutputStream param,
			boolean bEncodeParam) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException{
		Cipher cipher = encrypt_pub(AliceKey, BobId, param);
		byte[] buf = new byte[4096];
		
		if(bEncodeParam){ //if wants to output algParam to os too
			os.write(cipher.getParameters().getEncoded());
		}
		
		CipherInputStream cis = new CipherInputStream(is, cipher);
		
		while(true){
			int len = cis.read(buf);
			if( -1 == len )
				break;
			os.write(buf, 0, len);
		}		
	}
	
	/**
	 * Decrypt the given cipherData, with the receiver(Bob)'s private key and
	 * Sender(Alice)'s id
	 * @param cipherData the cipher text
	 * @param BobKey the receiver's private key
	 * @param AliceId the sender's id
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
	 * @param is
	 * @param BobKey
	 * @param AliceId
	 * @param param
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
			int len = is.read(buf);
			if( -1 == len ){ //eof
				break;
			}
			bos.write(buf, 0, len);
		}
		
		return bos.toByteArray();
	}
	
	/**
	 * decrypt the data from given InputStream, output the decrypted data to given OutputStream
	 * @param is the InputStram where encrypted data comes from
	 * @param os the OutputStream where decrypted data goes to
	 * @param BobKey the recver's PrivateKey
	 * @param AliceId the sender's ID
	 * @param param [OPTIONAL][in] the AlgorithmParameters for Cipher, if null,  will try to extract param from the head of {@code is}	 
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
			String AliceId, 
			AlgorithmParameters param
			)
	throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException{
		
		byte[] buf = new byte[4096];
		if( null == param ){ //if param == null, then extract AlgorithmParameter from head of 'is'
			param = extractAlgParameterFromInputStreamHead(is);
		}		
		Cipher cipher = decrypt_pub(BobKey, AliceId, param);
		
		CipherInputStream cis = new CipherInputStream(is, cipher);
		while(true){
			int len = cis.read(buf);
			if( -1 == len )
				break; //eof			
			os.write(buf, 0, len);			
		}	
	}

	private AlgorithmParameters extractAlgParameterFromInputStreamHead(
			InputStream is) throws IOException, NoSuchAlgorithmException,
			InvalidParameterSpecException {
		AlgorithmParameters param;
		byte[] tmpbuf = new byte[256];
		is.read(tmpbuf, 0, 2);
		is.read(tmpbuf, 2, tmpbuf[1]);
		byte[] encodedAlgParam = ByteBuffer.wrap(tmpbuf, 0, tmpbuf[1]+2).array();
		param = AlgorithmParameters.getInstance("IES");
		InitAlgParam(encodedAlgParam, param);
		return param;
	}
	
	/**
	 * Digest given data with specified algorithm, return the digest.
	 * @param data
	 * @param alg
	 * @return the produced digest
	 * @throws NoSuchAlgorithmException 
	 */
	static public byte[] Digest(byte[] data, String alg) throws NoSuchAlgorithmException{
		MessageDigest dgstAlg = MessageDigest.getInstance(alg);
		return dgstAlg.digest(data);		
	}
	
	/**
	 * generate a group of private keys according to a group of ids
	 * @param ids
	 * @param secmatrix
	 * @return
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
	 * @param parameters
	 * @param algParam 
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
		System.out.println("p1:" + new String(Hex.encode(p1)));
		System.out.println("p2:" + new String(Hex.encode(p2)));
		System.out.println("p3:" + String.valueOf(p3));
		algParam.init(spec);
	}
	
	/**
	 * this private function extracts some common parts for all versions of Encrypt()
	 * @param AliceKey
	 * @param BobId
	 * @param param
	 * @return
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
	 * @param BobKey the recver's private key
	 * @param AliceId the sender's ID
	 * @param param the AlgorithmParameter to init Cipher
	 * @return init-ed Cipher
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
