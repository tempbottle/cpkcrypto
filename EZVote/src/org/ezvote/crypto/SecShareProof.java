package org.ezvote.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.ezvote.util.Utility;

/**
 * make a proof that:
 *  Pj     Wj  
 *  --  =  --    == sj (Authority's secret share)
 *  G      X  
 *  where Pj = sj*G, Pj is the authority's public share for generating global public key 
 *  X is from the final cipher text {X, Y},
 *  Wj is used for decrypt the final cipher text cooperately;  
 *  this proof must prove that [Pj/G == Wj/X] and never reveal the sj
 *  
 *  The functionalities include:
 *  1. make proof
 *  2. verify proof
 *  3. serial/deserial proof
 * @author Red
 */
public class SecShareProof {
	
	private static Logger _log = Logger.getLogger(SecShareProof.class);
	
	private ECPoint _a, _b;
	private BigInteger _r;
	
	private SecShareProof(){}
	
	/**
	 * make a proof (as description said)
	 * @param ecParam the EC curve related parameters
	 * @param X the cipher text's x field
	 * @param Sj the authority's secret share
	 * @return built proof
	 * @throws NoSuchAlgorithmException 
	 */
	public static SecShareProof createProof(
			ECParameterSpec ecParam, 
			ECPoint X, 
			BigInteger Sj) throws NoSuchAlgorithmException{
		SecShareProof ssp = new SecShareProof();
		ECPoint G = ecParam.getG();
		int bitlen = ecParam.getN().bitLength();
		BigInteger k = new BigInteger(bitlen, new SecureRandom());
		
		ssp._a = G.multiply(k); //a = k*G
		ssp._b = X.multiply(k); //b = k*X
		
		BigInteger c = makeChallenge(ssp);
		
		ssp._r = k.add(Sj.multiply(c)); //r = k+c*sj 
			
		return ssp;
	}
	
	private static BigInteger makeChallenge(SecShareProof p)
	throws NoSuchAlgorithmException {
		MessageDigest dgst = MessageDigest.getInstance(Utility.DGSTALG);
		dgst.update(p._a.getEncoded());
		dgst.update(p._b.getEncoded());
		byte[] bytesC = dgst.digest();

		return new BigInteger(bytesC);
	}	
	
	/**
	 * verify this proof's validity
	 * @param Pj the public share of the authority with Pj = sj * G
	 * @param Wj the share published by authority with Wj = sj * X
	 * @param G the ec curve's generator
	 * @param X the final ciphertext's x field
	 * @return whether valid
	 * @throws NoSuchAlgorithmException 
	 */
	public boolean verifyProof(ECPoint Pj, ECPoint Wj, ECPoint G, ECPoint X) throws NoSuchAlgorithmException{
		boolean result = false;
		do{
			BigInteger c = makeChallenge(this);
			ECPoint rG = G.multiply(_r);
			ECPoint rX = X.multiply(_r);
			if(! rG.equals(_a.add(Pj.multiply(c)))) break; // r*G == a + c*Pj
			if(! rX.equals(_b.add(Wj.multiply(c)))) break; // r*X == b + c*Wj 
			result = true;
		}while(false);		
		return result;
	}
	
	/**
	 * serialize this proof to byte[]
	 * @return byte[] repr.
	 */
	public byte[] serialize(){		
		return serialToSeq().getDEREncoded();
	}
	
	public DERSequence serialToSeq(){
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(new X9ECPoint(_a));
		vec.add(new X9ECPoint(_b));
		vec.add(new DEROctetString(_r.toByteArray()));
		
		return new DERSequence(vec);
	}
	
	/**
	 * deserialize byte[] repr. to SecShareProof inst.
	 * @param ecParam EC parameters
	 * @param bytesProof the proof's byte[] repr.
	 * @return built SecShareProof inst.
	 * @throws IOException
	 */
	public static SecShareProof deserialize(ECParameterSpec ecParam, byte[] bytesProof) throws IOException{
		ASN1InputStream is = new ASN1InputStream(bytesProof);
		DERSequence seq = (DERSequence)is.readObject();
		ECPoint a = new X9ECPoint(ecParam.getCurve(), (ASN1OctetString)seq.getObjectAt(0)).getPoint();
		ECPoint b = new X9ECPoint(ecParam.getCurve(), (ASN1OctetString)seq.getObjectAt(1)).getPoint();
		BigInteger r = new BigInteger(((ASN1OctetString)seq.getObjectAt(2)).getOctets());
		
		SecShareProof ssp = new SecShareProof();
		
		ssp._a = a;
		ssp._b = b;
		ssp._r = r;
		return ssp;
	}
}
