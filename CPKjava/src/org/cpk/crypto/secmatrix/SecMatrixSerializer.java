package org.cpk.crypto.secmatrix;

import java.io.IOException;

/**
 * This interface is used to serialize/de-serialize secret matrix
 * @author zaexage@gmail.com
 */
public interface SecMatrixSerializer {
	public SecMatrix GetSecMatrix() throws IOException;
	public void ExportSecMatrix(SecMatrix secmatrix) throws IOException;
}
