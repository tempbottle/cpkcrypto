package org.cpk.crypto.secmatrix;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.cpk.crypto.MapAlg;
import org.cpk.crypto.MapAlgMgr;
import org.cpk.crypto.MappingAlgorithmException;
import org.cpk.crypto.pubmatrix.PubMatrix;

/**
 * Secret matrix is used to derive user's private key from given id. 
 * Also, client could use an instance of SecMatrix to generate a corresponding {@link org.cpk.crypto.pubmatrix.PubMatrix PubMatrix} 
 * @author zaexage@gmail.com
 */
public class SecMatrix {
	static private Logger logger = Logger.getLogger(SecMatrix.class);
	
	// member variables , NOTE: some variables are default access
	Vector<BigInteger> m_matrix; 
	MapAlg m_mapAlg;
	ECParameterSpec m_ecParam;
	URI m_domainURI;
	private SecureRandom m_random;
	private KeyFactory m_keyFactory = null; //only usable when BC provider is added
	
	/**
	 * constructor 
	 */
	SecMatrix() throws NoSuchAlgorithmException{
		m_random = new SecureRandom();	
		if(BCSetting.getInstance().IsUseBCProvider())
			m_keyFactory = KeyFactory.getInstance("ECDSA");
	}
	
	/**
	 * create a new instance of SecMatrix
	 * @param row the number of rows in matrix
	 * @param col the number of cols in matrix
	 * @param curveName the elliptic curve's name, refer to OpenSSL for a list, or `prime192v1' would do.
	 * @param mapAlgName the name of mapping algorithm, which is used to map the id to a vector of index into Matrix. For now, "DigestMap_SHA512" will do
	 * @param domainURI an optional URI for the matrix
	 * @return a new instance of SecMatrix
	 * @throws NoSuchAlgorithmException
	 * @throws SecurityException
	 * @throws IllegalArgumentException
	 * @throws NoSuchMethodException
	 * @throws InstantiationException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 * @throws ClassNotFoundException
	 */
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
	
	/**
	 * derive corresponding {@link org.cpk.crypto.pubmatrix.PubMatrix public matrix} from this SecMatrix
	 * @return PubMatrix instance
	 * @throws NoSuchAlgorithmException 
	 */
	public PubMatrix DerivePubMatrix() throws NoSuchAlgorithmException{
		return PubMatrix.GeneratePubMatrix(m_matrix, m_mapAlg, m_ecParam, m_domainURI);
	}
	
	/**
	 * retrieve Elliptic curve parameters
	 * @return ECParameterSpec instance
	 */
	public ECParameterSpec GetEcParam(){
		return m_ecParam;
	}
	
	/**
	 * make a mapping <id, SecMatrix> -> private key 
	 * @param id any string of id
	 * @return corresponding private key
	 * @throws InvalidKeySpecException
	 * @throws MappingAlgorithmException
	 */
	public PrivateKey GeneratePrivateKey(String id) 
		throws InvalidKeySpecException, MappingAlgorithmException{
		BigInteger biPrivkey = BigInteger.ZERO;
		try{			
			Vector<Integer> indices = null;
			try{
				 indices = m_mapAlg.doMap(id, m_matrix.size());
			}catch(Exception ex){
				logger.error(ex.getMessage(), ex);
				throw new MappingAlgorithmException("Failed to execute method doMap");
			}
			
			for(int i=0; i<indices.size(); ++i){
				int index = indices.get(i);				
				biPrivkey = biPrivkey.add(m_matrix.get(index));
			}
			ECPrivateKeySpec privSpec = new ECPrivateKeySpec(biPrivkey, m_ecParam);
			
			PrivateKey priKey = null;
			if( BCSetting.getInstance().IsUseBCProvider() ){
				priKey = m_keyFactory.generatePrivate(privSpec);
			}else{
				priKey = new JCEECPrivateKey("ECDSA", privSpec);
			}
			return priKey;
		}catch(InvalidKeySpecException ex){
			logger.error("GeneratePrivateKey failed: privkey value=" + biPrivkey.toString(16));
			throw ex;
		}
	}
	
}
