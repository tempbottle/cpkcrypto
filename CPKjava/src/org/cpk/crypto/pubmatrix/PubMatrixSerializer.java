package org.cpk.crypto.pubmatrix;

import java.io.IOException;

public interface PubMatrixSerializer {
	public PubMatrix GetPubMatrix() throws IOException;
	public void ExportPubMatrix(PubMatrix pubmatrix) throws IOException;
}
