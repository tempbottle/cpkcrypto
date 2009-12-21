package org.cpk.crypto.pubmatrix;

import java.io.IOException;

/**
 * This interface is used to serialize/de-serialize public matrix
 * @author zaexage@gmail.com
 */
public interface PubMatrixSerializer {
	public PubMatrix GetPubMatrix() throws IOException;
	public void ExportPubMatrix(PubMatrix pubmatrix) throws IOException;
}
