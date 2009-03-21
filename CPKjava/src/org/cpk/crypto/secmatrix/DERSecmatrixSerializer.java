package org.cpk.crypto.secmatrix;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.cpk.crypto.MapAlgMgr;

public class DERSecmatrixSerializer implements SecMatrixSerializer {

	private Logger logger = Logger.getLogger(DERSecmatrixSerializer.class);
	private InputStream m_in;
	private OutputStream m_out;
	
	public DERSecmatrixSerializer(InputStream in, OutputStream out){
		m_in = in;
		m_out = out;
	}
	
	@Override
	public void ExportSecMatrix(SecMatrix secmatrix) throws IOException {
		// TODO Auto-generated method stub
		ASN1EncodableVector encVec = new ASN1EncodableVector();
		encVec.add(new DERInteger(1));
		encVec.add(new DERUTF8String(secmatrix.m_domainURI.toString()));		
		X9ECParameters ecparam = new X9ECParameters(
				secmatrix.m_ecParam.getCurve(),
				secmatrix.m_ecParam.getG(),
				secmatrix.m_ecParam.getN(),
				secmatrix.m_ecParam.getH(),
				secmatrix.m_ecParam.getSeed()
				);
		encVec.add(ecparam);
		encVec.add(new DERObjectIdentifier(secmatrix.m_mapAlg.getAlgIdentifier()));
		Vector<BigInteger> matrix = secmatrix.m_matrix;
		ASN1EncodableVector privec = new ASN1EncodableVector();
		for(int i=0; i<matrix.size(); ++i){
			privec.add(new DERInteger(matrix.get(i)));			
		}
		encVec.add(new DERSequence(privec));
		
		m_out.write(new DERSequence(encVec).getDEREncoded()); //output the whole lot
	}

	@Override
	public SecMatrix GetSecMatrix() throws IOException {
		// TODO Auto-generated method stub
		try{
			ASN1InputStream is = new ASN1InputStream(m_in);
			SecMatrix secmatrix = new SecMatrix();
			DERSequence topseq = (DERSequence)is.readObject();
			assert(((DERInteger)topseq.getObjectAt(0)).getValue().intValue() == 1);
			secmatrix.m_domainURI = new URI(((DERUTF8String)topseq.getObjectAt(1)).getString());
			X9ECParameters ecparam = new X9ECParameters((ASN1Sequence)topseq.getObjectAt(2));
			secmatrix.m_ecParam = new ECParameterSpec(
						ecparam.getCurve(),
						ecparam.getG(),
						ecparam.getN(),
						ecparam.getH(),
						ecparam.getSeed()
					);
			DERObjectIdentifier identifier = (DERObjectIdentifier)topseq.getObjectAt(3);
			secmatrix.m_mapAlg = MapAlgMgr.GetMapAlgByOID(identifier.getId());
			DERSequence privec = (DERSequence)topseq.getObjectAt(4);
			secmatrix.m_matrix = new Vector<BigInteger>(privec.size());
			for(int i=0; i<privec.size(); ++i){
				secmatrix.m_matrix.add(((DERInteger)privec.getObjectAt(i)).getValue());
			}
			
			return secmatrix;
		}catch(Exception ex){
			logger.error("DERSecmatrixSerializer.GetSecMatrix failed: " + ex.toString());
			throw new IOException(ex);
		}				
	}

}
