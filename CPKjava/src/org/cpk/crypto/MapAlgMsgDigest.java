package org.cpk.crypto;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Vector;

import org.apache.log4j.Logger;

/**
 * this class uses specified digest algorithm to compute a fixed length digest and use it to  
 * map to a vector of indices. if digest's bit-length < matrix's size, exception will be thrown 
 * NOTE: the bytes used will start from the low-end, e.g.:byte[0] is 0~7 
 */
public class MapAlgMsgDigest implements MapAlg {

	private String m_dgstName = null;
	private static Logger logger = Logger.getLogger(MapAlgMsgDigest.class);
	
	public MapAlgMsgDigest(String DigestAlgName){
		m_dgstName = DigestAlgName;
	}
	
	@Override
	public Vector<Integer> doMap(String id, int size)
		throws NoSuchAlgorithmException, UnsupportedEncodingException{
		MessageDigest dgst = MessageDigest.getInstance(m_dgstName);
		if ( dgst.getDigestLength() * 8 < size ){
			logger.error("the length of digest not long enough, algorithm length = " + dgst.getDigestLength() * 8);
			throw new IllegalArgumentException("the length of digest algorithm is not long enough");
		}
		byte[] d = dgst.digest(id.getBytes("UTF-8"));
		
		int count = size;
		Vector<Integer> v = new Vector<Integer>();
		for(int i=0; i<count; i+=8){
			byte b = d[i/8];
			if( b == 0) continue;
			for(int j=0; j<8 && i+j<count; ++j ){
				if ((b & 1) != 0){
					v.add(i+j); 
					//logger.debug("doMap: add: " + (i+j));
				}
				b >>= 1;
			}
		}
		
		return v;
	}
	
	public String getAlgIdentifier(){
		return "1.2.3.4.5";
	}

}
