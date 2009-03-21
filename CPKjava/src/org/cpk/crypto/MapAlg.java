package org.cpk.crypto;

import java.util.Vector;

public interface MapAlg {
	public Vector<Integer> doMap(String id, int size) throws Exception;
	public String getAlgIdentifier();
}
