package org.ezvote.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Vector;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.ezvote.authority.AuthorityInfo;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

public class Utility {
	
	public static final String ACK = "ACK";
	/**
	 * this class will send some content to the specified peer, with ThreadPool 
	 */
	private static class SendJob implements Runnable{
		
		private Document _doc;
		private String _selfId;
		private InetSocketAddress _targetAddr; //target addr
		private String _targetId; 
		private SSLContext _sslCtx;
		private final boolean _bExpectACK;//expect peer return a <ACK> reply
		
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
			_bExpectACK = false;
		}
		
		private SendJob(Document newdoc,
				String selfId, 
				InetSocketAddress targetAddr, 
				String targetId, 
				SSLContext sslCtx,
				boolean expectACK){
			_doc = newdoc;
			_selfId = selfId;
			_targetAddr = targetAddr;
			_targetId = targetId;
			_sslCtx = sslCtx;
			_bExpectACK = expectACK;
		}
		
		@Override
		public void run(){
			SSLSocketFactory socFac = _sslCtx.getSocketFactory();
			SSLSocket socket = null;
			try {
				socket = (SSLSocket) socFac.createSocket(
						_targetAddr.getAddress(), _targetAddr.getPort());
				Utility.logOutConnection(socket, _selfId); //log connection
				BufferedWriter out = new BufferedWriter(
						new OutputStreamWriter(socket.getOutputStream(), Utility.ENCODING));
				Utility.XMLDocToWriter(_doc, out);			
				if(_bExpectACK){
					BufferedReader in = new BufferedReader(
							new InputStreamReader(socket.getInputStream(), Utility.ENCODING));
					Document doc = Utility.ReaderToXMLDoc(in);
					if(!doc.getRootElement().getName().equals(ACK)){ //if not ACK
						_log.error("The Peer didn't send ACK back");
					}
				}
				
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
	public final static String DGSTALG = "SHA-1"; //used in VoteProof
	public final static String ENCODING = "UTF-8";
	public final static String SIG_ALG = "ECDSA"; //the signature algorithm used
	public static final String KEYSPEC_ALG = "EC"; //the pub/private key algorithm
	
	public static final String TIMEZONE_STR = "GMT+8";
	private static Logger _log = Logger.getLogger(Utility.class);
	
	private static Pattern _pattern = Pattern.compile("CN=([^,]+)");
//	private static XMLOutputter _output = new XMLOutputter();
	
	///workers thread pool
	private static ExecutorService _workers = Executors.newFixedThreadPool(4);
	
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
			_log.debug("findYesVoteCount: voterCnt = " + voterCnt);
			ECPoint G = ecParam.getG();
			BigInteger order = ecParam.getN();
			ECPoint increment = G.add(G); //2G			
			BigInteger starter = BigInteger.valueOf(-voterCnt).mod(order);
			ECPoint curr = G.multiply(starter);
			for(int i=0; i<=voterCnt; ++i){
				if(curr.equals(clearText)){
					return i;
				}
				curr = curr.add(increment);
			}
		throw new MathException("calc YesVote failed");
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
	
	/**
	 * get password from console
	 */
	public static char[] getPasswordFromConsole(BufferedReader br) throws IOException {
		char[] password;		
		Console con = System.console();
		if( null != con ){
			password = con.readPassword();
		}else{			
			password = br.readLine().toCharArray();
			_log.debug("password="+new String(password));
		}
		return password;
	}
	
	/**
	 * retrieve peer's public key from given SSLSocket instance
	 * @throws SSLPeerUnverifiedException 
	 */
	public static PublicKey getPeerPubKey(SSLSocket soc) throws SSLPeerUnverifiedException {
		SSLSession session = soc.getSession();
		return session.getPeerCertificateChain()[0].getPublicKey();
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
	
	public static String getSubjectFromPrinciple(Principal principle) throws CertificateException{
		String dn = principle.getName();	
		_log.debug("principle.getName() = "+dn);
		Matcher m = _pattern.matcher(dn);
		if(! m.find() )
			throw new CertificateException("Unable to get CN from principle");
		
		return m.group(1);
	}
	
	public static void logInConnection(SSLSocket soc, String localId) throws SSLPeerUnverifiedException, CertificateException{
		String peerCN = getSubjectFromPrinciple(soc.getSession().getPeerPrincipal());
		_log.info("From: " + peerCN + " : "+ soc.getInetAddress().toString() + ":" + soc.getPort() + "\n"
				+ "To  : " + localId+ " : "+ soc.getLocalAddress().toString()+ ":" + soc.getLocalPort());
	}
	
	public static void logOutConnection(SSLSocket soc, String localId) throws SSLPeerUnverifiedException, CertificateException{
		String peerCN = getSubjectFromPrinciple(soc.getSession().getPeerPrincipal());
		_log.info("From: " + localId + " : "+ soc.getInetAddress().toString() + ":" + soc.getPort() + "\n"
				+ "To  : " + peerCN+ " : "+ soc.getLocalAddress().toString()+ ":" + soc.getLocalPort());
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
	 * read a single XML Document from reader and build a Document datastructure 
	 * @param r could be a socket underlying bufferedReader
	 * @return Document data-structure built from reader-content
	 * @throws IOException
	 * @throws JDOMException
	 */
	public static Document ReaderToXMLDoc(BufferedReader r) throws IOException, JDOMException{
		StringBuilder bdr = new StringBuilder();
		String line = null;
	
//		while(! (line = r.readLine()).isEmpty()){
//			bdr.append(line);
//		}
		
		while( true ){
			line = r.readLine();
			if( line.isEmpty() ) break;
			bdr.append(line+"\n");
		}
		
		_log.debug("ReaderToXMLDoc: " + bdr.toString());
		
		SAXBuilder saxbuilder = new SAXBuilder();
		Document doc = saxbuilder.build(new StringReader(bdr.toString()));
		return doc;
	}
	
	/**
	 * use Thread pool to async send document to peer(s)
	 */
	public static void sendXMLDocToPeer(
			Document newdoc, String selfId, InetSocketAddress addr, String id, SSLContext sslCtx){
		_workers.execute(new SendJob(newdoc, selfId, addr, id, sslCtx));
	}

	/**
	 * send the doc to peer synchronously, and wait for ACK from peer
	 */
	public static void syncSendXMLDocToPeer(
			Document newdoc, String selfId, Vector<AuthorityInfo> vinfos, SSLContext sslCtx)
	{
		Vector<Thread> thrs = new Vector<Thread>();
		for(AuthorityInfo vinfo : vinfos){
			InetSocketAddress addr = vinfo.get_addr();
			String id = vinfo.get_authId();
			Thread thr = new Thread(new SendJob(newdoc, selfId, addr, id, sslCtx, true));
			thrs.add(thr);
			try {
				XMLOutputter output = new XMLOutputter();
				StringWriter writer = new StringWriter();
				output.output(newdoc, writer);
				_log.debug("syncToPeer: " + writer.toString());
				thr.start();				
			} catch (IOException e) {
				_log.error("IOException while sync Send To Peer", e);
			}
		}
		
		for(Thread thr : thrs){
			try {
				thr.join();
			} catch (InterruptedException e) {
				_log.error("try to recv ACK: interrupted");
			}
		}
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

	public static String XMLDocToString(Document doc){
		XMLOutputter output = new XMLOutputter();
		String str = output.outputString(doc);
		return str;
	}

	public static void XMLDocToWriter(Document doc, Writer w) throws IOException{
		XMLOutputter output = new XMLOutputter();
		output.output(doc, w);
		
		StringWriter writer = new StringWriter();
		output.output(doc, writer);
		_log.debug("XMLDocToWriter: " + writer.toString());
		
		w.write("\n");
		w.flush();
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

}


