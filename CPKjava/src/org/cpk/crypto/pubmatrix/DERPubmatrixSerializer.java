package org.cpk.crypto.pubmatrix;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.cpk.crypto.MapAlgMgr;
import org.cpk.crypto.secmatrix.SecMatrix;

/**
 * This class could serialize/de-serialize {@link org.cpk.crypto.pubmatrix.PubMatrix PubMatrix} 
 * into/from DER encoding
 * @author zaexage@gmail.com
 * @see <a href=http://en.wikipedia.org/wiki/Distinguished_Encoding_Rules>DER encoding</a>
 */
public class DERPubmatrixSerializer implements PubMatrixSerializer {

	private static Logger logger = Logger.getLogger(DERPubmatrixSerializer.class);
	private InputStream m_in;
	private OutputStream m_out;
	
	/**
	 * initialize, the two parameters are both optional.
	 * if client needs to export public matrix, then the `out' parameter must be given;
	 * if client needs to import public matrix, then the `in' parameter must be given;   
	 * @param in an InputStream instance which connects to a DER encoded PubMatrix
	 * @param out an OutputStream instance where the PubMatrix will be output
	 */
	public DERPubmatrixSerializer(InputStream in, OutputStream out){
		m_in = in;
		m_out = out;
	}
	
	/**
	 * export the PubMatrix to the OutputStream set at initialization
	 * @param pubmatrix the public matrix need to be exported
	 * @throws IOException
	 */
	public void ExportPubMatrix(PubMatrix pubmatrix) throws IOException {
		ASN1EncodableVector encVec = new ASN1EncodableVector();
		encVec.add(new DERInteger(1));
		encVec.add(new DERUTF8String(pubmatrix.m_domainURI.toString()));		
		X9ECParameters ecparam = new X9ECParameters(
				pubmatrix.m_ecParam.getCurve(),
				pubmatrix.m_ecParam.getG(),
				pubmatrix.m_ecParam.getN(),
				pubmatrix.m_ecParam.getH(),
				pubmatrix.m_ecParam.getSeed()
				);
		encVec.add(ecparam);
		encVec.add(new DERObjectIdentifier(pubmatrix.m_mapAlg.getAlgIdentifier()));
		Vector<ECPoint> matrix = pubmatrix.m_matrix;
		ASN1EncodableVector privec = new ASN1EncodableVector();
		for(int i=0; i<matrix.size(); ++i){
			privec.add(new X9ECPoint(matrix.get(i)));			
		}
		encVec.add(new DERSequence(privec));
		
		m_out.write(new DERSequence(encVec).getDEREncoded()); //output the whole lot
	}

	/**
	 * import a Public matrix from InputStream set at initialization
	 * @return the public matrix de-serialized from InputStream
	 */
	public PubMatrix GetPubMatrix() throws IOException {
		try{
			ASN1InputStream is = new ASN1InputStream(m_in);
			PubMatrix pubmatrix = new PubMatrix();
			DERSequence topseq = (DERSequence)is.readObject();
			assert(((DERInteger)topseq.getObjectAt(0)).getValue().intValue() == 1);
			pubmatrix.m_domainURI = new URI(((DERUTF8String)topseq.getObjectAt(1)).getString());
			X9ECParameters ecparam = new X9ECParameters((ASN1Sequence)topseq.getObjectAt(2));
			pubmatrix.m_ecParam = new ECParameterSpec(
						ecparam.getCurve(),
						ecparam.getG(),
						ecparam.getN(),
						ecparam.getH(),
						ecparam.getSeed()
					);
			ECCurve curve = ecparam.getCurve();
			DERObjectIdentifier identifier = (DERObjectIdentifier)topseq.getObjectAt(3);
			pubmatrix.m_mapAlg = MapAlgMgr.GetMapAlgByOID(identifier.getId());
			DERSequence privec = (DERSequence)topseq.getObjectAt(4);
			pubmatrix.m_matrix = new Vector<ECPoint>(privec.size());
			for(int i=0; i<privec.size(); ++i){
				X9ECPoint pt = new X9ECPoint(curve, (ASN1OctetString)privec.getObjectAt(i));
				pubmatrix.m_matrix.add(pt.getPoint());
			}
			
			return pubmatrix;
		}catch(Exception ex){
			logger.error("DERSecmatrixSerializer.GetSecMatrix failed: " + ex.toString());
			throw new IOException(ex);
		}
	}

}
