package org.ezvote.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * this class is used to process ballot:
 * 1. encrypt
 * 2. decrypt
 * 3. homomorphic operations [by CipherText]
 * 4. make proof 
 * 5. serial/deserial cipher [by CipherText]
 * 
 * the cipherText is in a pair:
 * (x,y) = {k*G, msg + k*pubkey}, k is a random scalar, G is ec generator point, 
 * note that: `msg' and `pubkey' are both the ec point on the curve 
 * @author Red
 */
public class VoteCipher {
	private static Logger _log = Logger.getLogger(VoteCipher.class);
	
	private ECParameterSpec _ecParam; //the ec parameters
	private BigInteger _priKey; //the secret
	private ECPoint _pubKey; //the public key
	
	private SecureRandom _random = new SecureRandom();
	private int _bitlen;
	
	boolean _bCanDecrypt = false; //whether have private key
	
	/**
	 * init the VoteCipher with private key
	 */
	public VoteCipher(ECParameterSpec param, BigInteger prikey){
		_ecParam = param;
		_priKey = prikey;
		_pubKey = _ecParam.getG().multiply(_priKey);
		_bCanDecrypt = true;
		_bitlen = _ecParam.getN().bitLength();
	}
	
	/**
	 * init the VoteCipher only with public key
	 */
	public VoteCipher(ECParameterSpec param, ECPoint pubkey){
		_ecParam = param;
		_priKey = null;
		_pubKey = pubkey;
		_bCanDecrypt = false;
		_bitlen = _ecParam.getN().bitLength();
	}
	
	/**
	 * decrypt the CipherText, return the original msg
	 * @param ct CipherText instance
	 * @return the original msg
	 */
	public ECPoint decrypt(CipherText ct){
		assert(_bCanDecrypt == true);
		ECPoint neg = ct.getX().multiply(_priKey); //neg = k*G*prikey
		ECPoint msg = ct.getY().subtract(neg); //msg = Y - neg = omsg + k*pubkey - k*G*prikey = omsg
		return msg;
	}
	
	/**
	 * encrypt given msg
	 * @param msg the msg defined on the ECCurve
	 * @return CipherText inst
	 */
	public CipherText encrypt(ECPoint msg){
		BigInteger k = new BigInteger(_bitlen, _random);
		ECPoint g = _ecParam.getG();
		assert(msg.equals(g) || msg.equals(g.negate()));
		ECPoint x = g.multiply(k); // k*G
		ECPoint y = msg.add(_pubKey.multiply(k)); //msg + k*pubkey
		return new CipherText(x, y); //{k*G, msg+k*pubkey}
	}
	
	/**
	 * encrypt the clear text and make a proof that it's either G or -G
	 * @param msg the clear text , either G or -G
	 */
	public CipherTextWithProof encryptAndProve(ECPoint msg) throws ProofException{		
		BigInteger k = new BigInteger(_bitlen, _random);
		ECPoint g = _ecParam.getG();
		assert(msg.equals(g) || msg.equals(g.negate()));
		ECPoint x = g.multiply(k); // k*G
		ECPoint y = msg.add(_pubKey.multiply(k)); //msg + k*pubkey
		
		CipherText ct = new CipherText(x, y); //{k*G, msg+k*pubkey}
		
		VoteProof vp = VoteProof.createProof(_ecParam, _pubKey, msg, ct, k);
		
		return new CipherTextWithProof(ct, vp);
	}
}
