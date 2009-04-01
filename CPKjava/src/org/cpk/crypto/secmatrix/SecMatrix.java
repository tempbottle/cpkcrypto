package org.cpk.crypto.secmatrix;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.URI;
import java.util.Vector;
import org.cpk.crypto.MapAlg;
import org.cpk.crypto.MapAlgMgr;
import org.cpk.crypto.MappingAlgorithmException;
import org.cpk.crypto.pubmatrix.PubMatrix;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.KeyFactory;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;

import org.apache.log4j.Logger;

public class SecMatrix {
	static private Logger logger = Logger.getLogger(SecMatrix.class);
	
	/// member variables , NOTE: some variables are default access
	Vector<BigInteger> m_matrix; 
	MapAlg m_mapAlg;
	ECParameterSpec m_ecParam;
	URI m_domainURI;
	private SecureRandom m_random;
	private KeyFactory m_keyFactory;
	
	/**
	 * constructor, empty
	 */
	SecMatrix() throws NoSuchAlgorithmException{
		m_random = new SecureRandom();	
		m_keyFactory = KeyFactory.getInstance("ECDSA");
	}
	
	public static SecMatrix GenerateNewMatrix(int row, int col, String curveName, String mapAlgName, URI domainURI) throws NoSuchAlgorithmException, SecurityException, IllegalArgumentException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, ClassNotFoundException
	{
		SecMatrix inst = new SecMatrix();
		inst.m_mapAlg = MapAlgMgr.GetMapAlg(mapAlgName);
		inst.m_ecParam = ECNamedCurveTable.getParameterSpec(curveName);		
		inst.m_domainURI = domainURI;
		BigInteger N = inst.m_ecParam.getN();
		int bitlen = N.bitLength();
		inst.m_matrix = new Vector<BigInteger>(row*col);
		for(int i = 0; i<row*col; ++i){	//generate SecretMatrix			
			inst.m_matrix.add(i, new BigInteger(bitlen, inst.m_random));			
		}
		
		return inst;
	}
	
	public PubMatrix DerivePubMatrix() throws NoSuchAlgorithmException{
		return PubMatrix.GeneratePubMatrix(m_matrix, m_mapAlg, m_ecParam, m_domainURI);
	}
	
	public ECParameterSpec GetEcParam(){
		return m_ecParam;
	}
	
	public PrivateKey GeneratePrivateKey(String id) 
		throws InvalidKeySpecException, MappingAlgorithmException{
		BigInteger biPrivkey = BigInteger.ZERO;
		try{			
			Vector<Integer> indices = null;
			try{
				 indices = m_mapAlg.doMap(id, m_matrix.size());
			}catch(Exception ex){
				logger.error(ex.getMessage());
				throw new MappingAlgorithmException("Failed to execute method doMap");
			}
			
			for(int i=0; i<indices.size(); ++i){
				int index = indices.get(i);				
				biPrivkey = biPrivkey.add(m_matrix.get(index));
			}
			ECPrivateKeySpec privSpec = new ECPrivateKeySpec(biPrivkey, m_ecParam);
			return m_keyFactory.generatePrivate(privSpec);
		}catch(InvalidKeySpecException ex){
			logger.error("GeneratePrivateKey failed: privkey value=" + biPrivkey.toString(16));
			throw ex;
		}
	}
	
}
