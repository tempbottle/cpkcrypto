package org.ezvote.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

public class Utility {
	public final static String DGSTALG = "SHA-1"; //used in VoteProof
	public final static String ENCODING = "UTF-8";
	public final static String SIG_ALG = "ECDSA"; //the signature algorithm used
	public static final String KEYSPEC_ALG = "EC"; //the pub/private key algorithm
	public static final String TIMEZONE_STR = "GMT+8";
	
	private static Logger _log = Logger.getLogger(Utility.class);
	private static Pattern _pattern = Pattern.compile("CN=([^,]+),");
//	private static XMLOutputter _output = new XMLOutputter();
	
	///workers thread pool
	private static ExecutorService _workers = Executors.newFixedThreadPool(4);
	
	public static void sendXMLDocToPeer(
			Document newdoc, String selfId, InetSocketAddress addr, String id, SSLContext sslCtx){
		_workers.execute(new SendJob(newdoc, selfId, addr, id, sslCtx));
	}
	
	/**
	 * generate signature of the given String(in `ENCODING' encoding),
	 * output the result in BASE64 format
	 * @param content the content to be signed
	 * @return BASE64 format signature
	 * @throws NoSuchAlgorithmException 
	 * @throws UnsupportedEncodingException 
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 */
	public static String genSignature(PrivateKey priKey, String content) throws NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException, InvalidKeyException {
		try{
			Signature sig = Signature.getInstance(SIG_ALG);
			sig.initSign(priKey);
			sig.update(content.getBytes(ENCODING));
			byte[] bytesSignature = sig.sign();
			String signature = Base64.encodeBase64String(bytesSignature);
			
			return signature;
		}catch(NoSuchAlgorithmException ex){
			_log.error("unavailable signature algorithm: " + SIG_ALG);
			throw ex;
		} catch (InvalidKeyException ex) {
			_log.error("encountered invalid key during signature generation");
			throw ex;
		}
	}
	
	public static String XMLElemToString(Element... elems){
		Element[] es = elems;
		XMLOutputter out = new XMLOutputter();
		StringBuilder bdr = new StringBuilder();
		for(Element e : es){
			bdr.append(out.outputString(e));
		}
		return bdr.toString();
	}
	
	public static String XMLDocToString(Document doc){
		XMLOutputter output = new XMLOutputter();
		String str = output.outputString(doc);
		return str;
	}
	
	public static void XMLDocToWriter(Document doc, Writer w) throws IOException{
		XMLOutputter output = new XMLOutputter();
		output.output(doc, w);
		w.write("\n");
		w.flush();
	}
	
	/**
	 * read a single XML Document from reader and build a Document datastructure 
	 * @param r could be a socket underlying bufferedReader
	 * @return Document data-structure built from reader-content
	 * @throws IOException
	 * @throws JDOMException
	 */
	public static Document ReaderToXMLDoc(BufferedReader r) throws IOException, JDOMException{
		StringBuilder bdr = new StringBuilder();
		String line = null;
	
		while(! (line = r.readLine()).isEmpty()){
			bdr.append(line);
		}
		
		SAXBuilder saxbuilder = new SAXBuilder();
		Document doc = saxbuilder.build(new StringReader(bdr.toString()));
		return doc;
	}
	
	/**
	 * retrieve the subject's CN field from given certificate
	 * @param cert given certificate
	 * @return subject's CN field
	 * @throws CertificateException 
	 */
	public static String getSubjectFromCert(java.security.cert.X509Certificate cert) throws CertificateException{
		String dn = cert.getSubjectX500Principal().getName();		
		Matcher m = _pattern.matcher(dn);
		if(! m.find() )
			throw new CertificateException("Unable to get CN from certificate");
		
		return m.group(1);
	}
	
	public static String getSubjectFromPrinciple(X500Principal principle) throws CertificateException{
		String dn = principle.getName();		
		Matcher m = _pattern.matcher(dn);
		if(! m.find() )
			throw new CertificateException("Unable to get CN from principle");
		
		return m.group(1);
	}
	
	public static void logConnection(SSLSocket soc, String localId) throws SSLPeerUnverifiedException, CertificateException{
		String peerCN = getSubjectFromPrinciple((X500Principal)soc.getSession().getPeerPrincipal());
		_log.info("From: " + peerCN + " : "+ soc.getInetAddress().toString() + ":" + soc.getPort() + "\n"
				+ "To  : " + localId+ " : "+ soc.getLocalAddress().toString()+ ":" + soc.getLocalPort());
	}
	
	/**
	 * verify a BASE64-encoded signature
	 * @param content the content got signed, [in unified encoding, UTF-8]
	 * @param sig64 the signature in BASE64 encoding
	 * @param pubkey the public key
	 * @return whether valid
	 * @throws NoSuchAlgorithmException 
	 * @throws UnsupportedEncodingException 
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 */
	public static boolean VerifyBase64Sig(String content, String sig64, PublicKey pubkey) throws NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException, InvalidKeyException{
		Signature sig_ = Signature.getInstance(SIG_ALG);
		
		byte[] decodedSig = Base64.decodeBase64(sig64);
		sig_.initVerify(pubkey);
		sig_.update(content.getBytes(ENCODING));
		return sig_.verify(decodedSig);
	}

	/**
	 * parse the string, create the InetSocketAddress from that;
	 * expected format: ip:port or host:port
	 * @param addr the string format of address
	 * @return corresponding InetSocketAddress
	 */
	public static InetSocketAddress parseInetSocketAddress(String addr) {
		String[] parts = addr.split(":");
		if( parts.length != 2){
			_log.error("Wrong format of InetSocketAddres:"+addr);
			return null;
		}
		return InetSocketAddress.createUnresolved(parts[0], Integer.parseInt(parts[1]));
	}
	
	/**
	 * this class will send some content to the specified peer, with ThreadPool 
	 */
	private static class SendJob implements Runnable{
		
		private Document _doc;
		private String _selfId;
		private InetSocketAddress _targetAddr; //target addr
		private String _targetId; 
		private SSLContext _sslCtx;		
		
		private SendJob(Document newdoc,
				String selfId, 
				InetSocketAddress targetAddr, 
				String targetId, 
				SSLContext sslCtx){
			_doc = newdoc;
			_selfId = selfId;
			_targetAddr = targetAddr;
			_targetId = targetId;
			_sslCtx = sslCtx;			
		}
		
		@Override
		public void run(){
			SSLSocketFactory socFac = _sslCtx.getSocketFactory();
			SSLSocket socket = null;
			try {
				socket = (SSLSocket) socFac.createSocket(
						_targetAddr.getAddress(), _targetAddr.getPort());
				Utility.logConnection(socket, _selfId); //log connection
				BufferedWriter out = new BufferedWriter(
						new OutputStreamWriter(socket.getOutputStream(), Utility.ENCODING));
				Utility.XMLDocToWriter(_doc, out);			
				
			} catch (Exception e) {
				_log.error("SendJob failed", e);
			} finally{
				try {
					if(null != socket)
						socket.close();
				} catch (IOException e) {
					_log.error("close sendjob socket failed", e);
				}
			}
			
		}
	}

	/**
	 * given the clearText in form of: m*G, find YesCnt 
	 * where m = YesCnt - NoCnt; 
	 * as    voterCnt = YesCnt + NoCnt
	 * so    YesCnt = (m + voterCnt)/2  
	 * @param clearText the ECPoint of m*G
	 * @param ecParam the ECParameter
	 * @param voterCnt how many voters in total
	 * @return YesCnt
	 * @throws MathException 
	 */
	public static int findYesVoteCount(ECPoint clearText,
			ECParameterSpec ecParam, int voterCnt) throws MathException {
			ECPoint G = ecParam.getG();
			ECPoint increment = G.add(G); //2G
			ECPoint curr = G.multiply(BigInteger.valueOf(-voterCnt));
			for(int i=0; i<=voterCnt; ++i){
				if(curr.equals(clearText)){
					return i;
				}
				curr.add(increment);
			}
		throw new MathException("calc YesVote failed");
	} 
}


