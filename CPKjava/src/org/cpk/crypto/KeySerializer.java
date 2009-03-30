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
 * @author ZaeXage
 */
public class KeySerializer {
	
	public static byte[] ToByteArray(PrivateKey prikey){
		return prikey.getEncoded();
	}
	public static byte[] ToByteArray(PublicKey pubkey){
		return pubkey.getEncoded();
	}
	
	public static void PutPrivateKeyToFile(PrivateKey prikey, String filename) throws IOException{
		byte[] bytes = ToByteArray(prikey);
		FileOutputStream fos = new FileOutputStream(filename);
		fos.write(bytes);
		fos.close();
	}
	
	public static void PutPublicKeyToToFile(PublicKey pubkey, String filename) throws IOException{
		byte[] bytes = ToByteArray(pubkey);
		FileOutputStream fos = new FileOutputStream(filename);
		fos.write(bytes);
		fos.close();
	}
	
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
