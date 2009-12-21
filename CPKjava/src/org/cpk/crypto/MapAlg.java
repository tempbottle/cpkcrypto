package org.cpk.crypto;

import java.util.Vector;

/**
 * Mapping algorithm maps an id to the a vector of indices,
 * which are used by {@link org.cpk.crypto.secmatrix.SecMatrix SecMatrix} and {@link org.cpk.crypto.pubmatrix.PubMatrix PubMatrix}
 * to generate corresponding private/public key;<br>
 * every algorithm should be assigned an OID. <br>
 * [well, you could give it an arbitrary temporary oid anyway] 
 * @author zaexage@gmail.com
 * @see <a href="http://en.wikipedia.org/wiki/Object_identifier">OID</a>
 */
public interface MapAlg {
	/**
	 * map an id to a vector of indices into PubMatrix/SecMatrix
	 * @param id the id used to generate public/private key
	 * @param size the public/private matrix's size
	 * @return a vector of indices into matrix
	 * @throws Exception
	 */
	public Vector<Integer> doMap(String id, int size) throws Exception;
	/**
	 * return the algorithm's OID String
	 * @return the String representation of OID
	 */
	public String getAlgIdentifier(); ///return the algorithm's OID
}
