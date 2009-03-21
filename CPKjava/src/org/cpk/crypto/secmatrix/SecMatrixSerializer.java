package org.cpk.crypto.secmatrix;

import java.io.IOException;

public interface SecMatrixSerializer {
	public SecMatrix GetSecMatrix() throws IOException;
	public void ExportSecMatrix(SecMatrix secmatrix) throws IOException;
}
