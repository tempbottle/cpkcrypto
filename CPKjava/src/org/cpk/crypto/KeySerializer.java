/**
 * this class is used to im/export the PrivateKey and PublicKey 
 */
package org.cpk.crypto;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * an utility class to serialize/de-serialize public key and private key  
 * @author zaexage@gmail.com
 */
public class KeySerializer {
	
	/**
	 * encode the Private Key instance to byte[]
	 * @param prikey the private key instance
	 * @return the encoded private key
	 */
	public static byte[] ToByteArray(PrivateKey prikey){
		return prikey.getEncoded();
	}
	
	/**
	 * encode the Public Key instance to byte[] 
	 * @param pubkey the public key instance 
	 * @return the encoded public key
	 */
	public static byte[] ToByteArray(PublicKey pubkey){
		return pubkey.getEncoded();
	}
	
	/**
	 * output encoded private key to specified file
	 * @param prikey the private key to be encoded and output
	 * @param filename the file where the encoded key output
	 * @throws IOException
	 */
	public static void PutPrivateKeyToFile(PrivateKey prikey, String filename) throws IOException{
		byte[] bytes = ToByteArray(prikey);
		FileOutputStream fos = new FileOutputStream(filename);
		fos.write(bytes);
		fos.close();
	}
	
	/**
	 * output encoded public key to specified file
	 * @param pubkey the public key to be encoded and output
	 * @param filename the file where the encoded key output
	 * @throws IOException
	 */
	public static void PutPublicKeyToToFile(PublicKey pubkey, String filename) throws IOException{
		byte[] bytes = ToByteArray(pubkey);
		FileOutputStream fos = new FileOutputStream(filename);
		fos.write(bytes);
		fos.close();
	}
	
	/**
	 * retrieve a private key from specified file
	 * @param filename the file where to retrieve the private key
	 * @return PrivateKey instance
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey GetPrivateKeyFromFile(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		FileInputStream fis = new FileInputStream(filename);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		byte[] buf = new byte[1024];
		while(true){
			int cnt = fis.read(buf);
			if( cnt == -1 ) //read EOF
				break;
			bos.write(buf, 0, cnt);
		}
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bos.toByteArray());
		KeyFactory factory = KeyFactory.getInstance("EC");
		PrivateKey prikey = factory.generatePrivate(spec);
		
		return prikey;
	}
	
	/**
	 * retrieve a public key from specified file
	 * @param filename the file where to retrieve the public key
	 * @return PublicKey instance
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PublicKey GetPublicKeyFromFile(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		FileInputStream fis = new FileInputStream(filename);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		byte[] buf = new byte[1024];
		while(true){
			int cnt = fis.read(buf);
			if( cnt == -1 ) //read EOF
				break;
			bos.write(buf, 0, cnt);
		}
		X509EncodedKeySpec spec = new X509EncodedKeySpec(bos.toByteArray());
		KeyFactory factory = KeyFactory.getInstance("EC");
		PublicKey pubkey = factory.generatePublic(spec);
		
		return pubkey;
	}	
}
