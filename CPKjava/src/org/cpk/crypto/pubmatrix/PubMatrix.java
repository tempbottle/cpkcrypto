package org.cpk.crypto.pubmatrix;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.cpk.crypto.MapAlg;
import org.cpk.crypto.MappingAlgorithmException;

/**
 * this class is used to generate public key from an ID.
 * the instance of this class should be created by an instance 
 * of {@link org.cpk.crypto.secmatrix.SecMatrix SecMatrix}.
 * @author zaexage@gmail.com
 */
public class PubMatrix {
	
	// member variables
	static private Logger logger = Logger.getLogger(PubMatrix.class);
	Vector<ECPoint> m_matrix;
	MapAlg m_mapAlg;
	ECParameterSpec m_ecParam;
	URI m_domainURI;
	private KeyFactory m_keyFactory;
	
	// methods
	PubMatrix() throws NoSuchAlgorithmException{
		logger.debug("PubMatrix instance constructed");
		m_keyFactory = KeyFactory.getInstance("ECDSA");		
	}
	
	/**
	 * only called by SecMatrix.DerivePubMatrix(). Client should not try calling this.
	 * @param secmatrix the secret matrix from a SecMatrix instance
	 * @param alg the mapping algorithm used by SecMatrix
	 * @param param the EC Parameter used by SecMatrix
	 * @return a PubMatrix instance that derived from a SecMatrix instance
	 * @throws NoSuchAlgorithmException
	 */
	public static PubMatrix GeneratePubMatrix(
			Vector<BigInteger> secmatrix,
			MapAlg alg,
			ECParameterSpec param,
			URI domainURI			
			) throws NoSuchAlgorithmException
	{
		PubMatrix mat = new PubMatrix();
		mat.m_mapAlg = alg;
		mat.m_ecParam = param;		
		mat.m_domainURI = domainURI;
				
		ECPoint G = param.getG();
				
		mat.m_matrix = new Vector<ECPoint>(secmatrix.size());
		for(int i=0; i<secmatrix.size(); ++i){ //generate PubMatrix
			ECPoint pt = G.multiply(secmatrix.get(i));
			mat.m_matrix.add(i, pt);			
		}
		
		return mat;
	}
	
	/**
	 * retrieve the {@link org.bouncycastle.jce.spec.ECParameterSpec ECParameterSpce}
	 * @return elliptic curve parameters spec
	 */
	public ECParameterSpec GetEcParam(){
		return m_ecParam;
	}	
	
	/**
	 * Generate a public key from an ID (possibly, a receiver's email address).
	 * the ID is transformed with some mapping algorithm {@link org.cpk.crypto.MapAlg MapAlg},
	 * then the corresponding public key is generated. 
	 * @param id the receiver's id
	 * @return generated public key
	 * @throws InvalidKeySpecException
	 * @throws MappingAlgorithmException
	 */
	public PublicKey GeneratePublicKey(String id)
		throws InvalidKeySpecException, MappingAlgorithmException
		{
		ECPoint pt = null;
		try{
			Vector<Integer> indices = null;
			try{
				indices = m_mapAlg.doMap(id, m_matrix.size());
			}catch(Exception ex){
				logger.error(ex.getMessage());
				throw new MappingAlgorithmException("Failed to execute method doMap()");
			}
			
			int index = indices.get(0);
			pt = m_matrix.get(index);		
				
			for(int i=1; i<indices.size(); ++i){
				index = indices.get(i);		
				pt = pt.add(m_matrix.get(index));
			}
			ECPublicKeySpec pubSpec = new ECPublicKeySpec(
					pt, m_ecParam);
			
			PublicKey pubKey = m_keyFactory.generatePublic(pubSpec);
			return pubKey;
		}catch(InvalidKeySpecException ex){
			logger.error("GeneratePublicKey failed: publicKey value= ("
					+ pt.getX().toBigInteger() + ", " + pt.getY().toBigInteger() + ")");
			throw ex;
		}
	}
}
