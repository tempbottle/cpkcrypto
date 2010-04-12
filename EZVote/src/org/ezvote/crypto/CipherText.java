package org.ezvote.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * cipherText in a pair {x, y} = {k*G, msg + k*pubkey}
 * this class will deal with serial/deserial work
 * @see org.ezvote.crypto.VoteCipher 
 * @author Red
 */
public class CipherText {
	private static Logger _log = Logger.getLogger(CipherText.class);
	
	ECPoint _x, _y;
	
	CipherText(ECPoint x, ECPoint y){
		_x = x; _y = y;
	}
	
	/**
	 * serialize this CipherText to bytes in ASN.1 format
	 * @return
	 * @throws CryptoException
	 */
	public byte[] serialize(){
		return serialToSeq().getDEREncoded();		
	}
	
	public DERSequence serialToSeq(){
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(new X9ECPoint(_x));
		vec.add(new X9ECPoint(_y));
		return new DERSequence(vec);
	}
	
	/**
	 * deserialize bytes in ASN.1 format to form the CipherText instance
	 * @param curve the ECCurve
	 * @param bytes the cipherText in ASN.1 format
	 * @return built CipherText instance
	 * @throws CryptoException
	 */
	public static CipherText deserialize(ECCurve curve, byte[] bytes) throws CryptoException{
		try{
			ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
			ASN1InputStream is = new ASN1InputStream(bais);

			DERSequence seq = (DERSequence)is.readObject();
			ECPoint x = new X9ECPoint(curve, (ASN1OctetString) seq.getObjectAt(0)).getPoint();
			ECPoint y = new X9ECPoint(curve, (ASN1OctetString) seq.getObjectAt(1)).getPoint();
			CipherText inst = new CipherText(x, y);
			return inst;
		}catch(IOException e){
			_log.error("Failed to deserialize CipherText");
			throw new CryptoException("Failed to deserialize CipherText", e);
		}
	} 
	
	/**
	 * homomorphically add this ciphertext to another, return generated ciphertext
	 * @param ct another ciphertext
	 * @return generated ciphertext
	 */
	public CipherText HomoAdd(CipherText ct){
		ECPoint x = _x.add(ct._x);
		ECPoint y = _y.add(ct._y);		
		return new CipherText(x, y);
	}
	
	public ECPoint getX(){
		return _x;
	}
	
	public ECPoint getY(){
		return _y;
	}
}
