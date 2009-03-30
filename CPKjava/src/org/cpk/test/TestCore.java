package org.cpk.test;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.cpk.crypto.secmatrix.*;
import org.cpk.crypto.pubmatrix.*;
import org.cpk.crypto.CPKUtil;
import org.cpk.crypto.KeySerializer;
import org.cpk.crypto.MapAlgMgr;

import org.cpk.cms.PKCS7;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Vector;

public class TestCore {
	private static Logger logger = Logger.getLogger(TestCore.class);
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try{		
			PropertyConfigurator.configure("log4j.properties");
			MapAlgMgr.Configure("MapAlg.properties", "OIDMapAlg.properties");
			
			logger.info("start to create secret matrix");
			SecMatrix secmatrix = SecMatrix.GenerateNewMatrix(16, 32, "prime192v1", "DigestMap_SHA512", new URI("cpk:alphaJava"));
			logger.info("start to create public matrix");
			PubMatrix pubmatrix = secmatrix.DerivePubMatrix();
			logger.info("public matrix creation done");
			
			BaseTest(secmatrix, pubmatrix);
			
			logger.info("BaseTest first pass : DONE");
			
			KeyImExportTest(secmatrix, pubmatrix);
			
			logger.info("export pri/pub keys : DONE");
			
			en_decryptStreamTest(secmatrix, pubmatrix);
			
			logger.info("en/de crypt stream test: DONE");
			
			/// test matrix export and import
			FileOutputStream secout = new FileOutputStream("secmatrix"); 
			FileInputStream secin = new FileInputStream("secmatrix");
			FileOutputStream pubout = new FileOutputStream("pubmatrix");
			FileInputStream pubin = new FileInputStream("pubmatrix");
			
			DERSecmatrixSerializer secSerial = new DERSecmatrixSerializer(secin, secout);
			secSerial.ExportSecMatrix(secmatrix);
			
			DERPubmatrixSerializer pubSerial = new DERPubmatrixSerializer(pubin, pubout);
			pubSerial.ExportPubMatrix(pubmatrix);
			
			logger.info(" export matrices : DONE");
			
			secmatrix = secSerial.GetSecMatrix();
			pubmatrix = pubSerial.GetPubMatrix();
			
			logger.info(" import matrices : DONE");			
			
			BaseTest(secmatrix, pubmatrix);
			
			logger.info("BaseTest second pass : DONE");
			
		}catch(Exception ex){
			ex.printStackTrace();
		}
	}

	private static void en_decryptStreamTest(SecMatrix secmatrix,
			PubMatrix pubmatrix) throws FileNotFoundException,
			InvalidKeyException, InvalidKeySpecException,
			NoSuchAlgorithmException, NoSuchPaddingException, IOException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, InvalidParameterSpecException {
		FileInputStream fis = new FileInputStream("SourceText");
		FileOutputStream fos = new FileOutputStream("EncryptedSourceText");
		CPKUtil util = new CPKUtil(secmatrix, pubmatrix);
		util.Encrypt(fis, fos, secmatrix.GeneratePrivateKey("zaex"), "zaex_recv", null, true);
		fis.close();
		fos.close();
		
		FileInputStream afis = new FileInputStream("EncryptedSourceText");
		fos = new FileOutputStream("DecryptedSourceText");
		util.Decrypt(afis, fos, secmatrix.GeneratePrivateKey("zaex_recv"), "zaex", null);
		
		afis.close();
		fos.close();
	}

	private static void KeyImExportTest(SecMatrix secmatrix, PubMatrix pubmatrix)
			throws InvalidKeySpecException, IOException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidParameterSpecException,
			InvalidAlgorithmParameterException {
		PrivateKey prikey = secmatrix.GeneratePrivateKey("zaex");
		PublicKey pubkey = pubmatrix.GeneratePublicKey("zaex_recv");						

		KeySerializer.PutPrivateKeyToFile(prikey, "prikey");
		KeySerializer.PutPublicKeyToToFile(pubkey, "pubkey");
		PrivateKey genPriKey = KeySerializer.GetPrivateKeyFromFile("prikey");
		PublicKey genPubKey = KeySerializer.GetPublicKeyFromFile("pubkey");
		
		CPKUtil util = new CPKUtil(secmatrix, pubmatrix);
		String srcStr = "Ohyeah";
		ByteArrayOutputStream param = new ByteArrayOutputStream();
		//byte[] cipherText = util.Encrypt(srcStr.getBytes(), genPriKey, "zaex_recv", param);
		
		Cipher cipher = Cipher.getInstance("ECIES");
		IEKeySpec spec = new IEKeySpec(genPriKey, genPubKey);
		cipher.init(Cipher.ENCRYPT_MODE, spec);
		byte[] cipherText = cipher.doFinal(srcStr.getBytes());
		param.write(cipher.getParameters().getEncoded());
		
		AlgorithmParameters algParam = AlgorithmParameters.getInstance("IES");
		CPKUtil.InitAlgParam(param.toByteArray(), algParam);
		byte[] clearText = util.Decrypt(cipherText, secmatrix.GeneratePrivateKey("zaex_recv"), "zaex", algParam);
		System.out.println("Test key export/import: clearText: "+new String(clearText));
	}
	
	private static void BaseTest(SecMatrix secmatrix, PubMatrix pubmatrix)
			throws InvalidKeySpecException, NoSuchAlgorithmException,
			InvalidKeyException, SignatureException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException,
			FileNotFoundException, IOException, InvalidParameterSpecException,
			NoSuchProviderException {
		logger.info("ready to generate private key");			
		PrivateKey priKey = secmatrix.GeneratePrivateKey("Goldman");
		
		logger.info("ready to generate public key");
		PublicKey pubKey = pubmatrix.GeneratePublicKey("Goldman");
		
		logger.info("ready to sign");
		Signature sigAlg = Signature.getInstance("ECDSA");
		String strToSign = "ComeOn,HurryUp,SignMeUp12";
		byte[] bytesToSign = strToSign.getBytes();
		
		sigAlg.initSign(priKey);
		sigAlg.update(bytesToSign);
		byte[] sig = sigAlg.sign();		
		
		System.out.println("Signature is:" + new String(Hex.encode(sig)));
			
		logger.info("ready to verify");
		sigAlg.initVerify(pubKey);
		sigAlg.update(bytesToSign);
		boolean verified = sigAlg.verify(sig);
		logger.info("verify done");
		System.out.println("The signature is: " + (verified ? "valid" : "invalid"));

		//////////////en/decrypt
//			KeyPairGenerator generator = KeyPairGenerator.getInstance("ECIES"); 
//			ECCurve curve = new ECCurve.Fp(
//		                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
//		                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
//		                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
//
//		    ECParameterSpec spec = new ECParameterSpec(
//		                curve,
//		                curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
//		                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n
//			ECParameterSpec spec = secmatrix.GetEcParam();
//			generator.initialize(spec, new SecureRandom());
//			KeyPair akeypair = generator.generateKeyPair();
//			PrivateKey aPriKey = akeypair.getPrivate();
//			PublicKey aPubKey = akeypair.getPublic();
//			KeyPair bkeypair = generator.generateKeyPair();
//			PrivateKey bPriKey = bkeypair.getPrivate();
//			PublicKey bPubKey = bkeypair.getPublic();
		
		PrivateKey aPriKey = secmatrix.GeneratePrivateKey("Alice");
		PublicKey aPubKey = pubmatrix.GeneratePublicKey("Alice");
		PrivateKey bPriKey = secmatrix.GeneratePrivateKey("Bob");
		PublicKey bPubKey = pubmatrix.GeneratePublicKey("Bob");
		Cipher aCipher = Cipher.getInstance("ECIES");
		Cipher bCipher = Cipher.getInstance("ECIES");
			
		String strToEncry = "Gordan Freeman";			
		
		
		IEKeySpec c1key = new IEKeySpec(aPriKey, bPubKey);
		IEKeySpec c2key = new IEKeySpec(bPriKey, aPubKey);
		
//			byte[] d = new byte[]{1,2,3,4,5,6,7,8};
//			byte[] e = new byte[]{8,7,6,5,4,3,2,1};
//			IESParameterSpec param = new IESParameterSpec(d,e,128);

		aCipher.init(Cipher.ENCRYPT_MODE, c1key);
		AlgorithmParameters param = aCipher.getParameters();
		bCipher.init(Cipher.DECRYPT_MODE, c2key, param);
		
		logger.info("ready to encrypt");
		byte[] cipherText = aCipher.doFinal(strToEncry.getBytes());			
		System.out.println("the cipher is:" + new String(Hex.encode(cipherText)) );						
		logger.info("ready to decrypt");
		byte[] clearText = bCipher.doFinal(cipherText);
		System.out.println("the cleartext is:" + new String(clearText));
		
		///test CPKUtil
		CPKUtil util = new CPKUtil(secmatrix, pubmatrix);
		byte[] utilsig = util.Sign(bytesToSign, "Alice");
		boolean bVerified = util.Verify(bytesToSign, utilsig, "Alice");
		System.out.println("CPKUtil. sign/verify: " + (bVerified?"OK":"FAILED"));
		
		///test PKCS7 signature
		PKCS7 pkcs7 = new PKCS7(util);
		Vector<String> signerIds = new Vector<String>();
		signerIds.add("Alice");
		byte[] pkcs7PackagedSig = pkcs7.Sign(bytesToSign, signerIds,
				CPKUtil.GeneratePrivateKeyFromId(signerIds, secmatrix), false);
		System.out.println("pkcs7packaged sig:"+new String(Hex.encode(pkcs7PackagedSig)));
		FileOutputStream fos = new FileOutputStream("pkcs7sig");
		fos.write(pkcs7PackagedSig);
		fos.close();
		
		bVerified = pkcs7.Verify(pkcs7PackagedSig, null);
		System.out.println("pkcs7PackagedSig :"+(bVerified?"OK":"FAILED"));
		
		///test PKCS7 encryption
		Vector<String> recverIds = new Vector<String>();
		recverIds.add("bob1"); 
		recverIds.add("bob2");
		byte[] envedbytes = pkcs7.Encrypt(strToEncry.getBytes("UTF-8"),
				secmatrix.GeneratePrivateKey("Alice"),
				"Alice",
				recverIds);
		
		byte[] decbytes = pkcs7.Decrypt(envedbytes, "bob2", 
				secmatrix.GeneratePrivateKey("bob2"));
		
		System.out.println("pkcs7 decrypted: " + new String(decbytes, "UTF-8") );
	}

}
