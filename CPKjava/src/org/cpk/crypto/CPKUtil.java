package org.cpk.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.DERObjectIdentifier;
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
			IESParameterSpec algspec = parameters.getParameterSpec(IESParameterSpec.class);
			System.out.println("Encrypt: p1: "+new String(Hex.encode(algspec.getDerivationV())));
			System.out.println("Encyrpt: p2: "+new String(Hex.encode(algspec.getEncodingV())));
			System.out.println("Encrypt: p3: "+String.valueOf(algspec.getMacKeySize()));
		}
		byte[] cipherText = cipher.doFinal(data);
		
		System.out.println("Encrypt: cipherText: " + new String(Hex.encode(cipherText)));
		return cipherText;
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
		System.out.println("Decrypt: cipherData: "+new String(Hex.encode(cipherData)));
		System.out.println("Decrypt: SenderId: " + AliceId);
		PublicKey pubkey = m_pubmatrix.GeneratePublicKey(AliceId);
		Cipher cipher = Cipher.getInstance("ECIES");
//		IESParameterSpec paramSpec = new IESParameterSpec(
//				new byte[]{1,2,3,4,5,6,7,8},
//				new byte[]{8,7,6,5,4,3,2,1},
//				128
//			);
		IEKeySpec spec = new IEKeySpec(BobKey, pubkey);
		cipher.init(Cipher.DECRYPT_MODE, spec, param);
		
		byte[] clearText = cipher.doFinal(cipherData);
		return clearText;
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
	
	static public Vector<PrivateKey> GeneratePrivateKeyFromId(Vector<String> ids, SecMatrix secmatrix) throws InvalidKeySpecException, MappingAlgorithmException{
		Vector<PrivateKey> keys = new Vector<PrivateKey>(ids.size());
		for(int i=0; i<ids.size(); ++i){
			keys.add(secmatrix.GeneratePrivateKey(ids.get(i)));
		}
		return keys;
	}
	
}
