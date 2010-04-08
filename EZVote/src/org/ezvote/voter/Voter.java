package org.ezvote.voter;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ezvote.ConfigException;
import org.ezvote.RegisterException;
import org.ezvote.authority.AuthorityInfo;
import org.ezvote.manager.Manager;
import org.ezvote.manager.ManagerInfo;
import org.ezvote.util.Dispatcher;
import org.ezvote.util.DispatcherException;
import org.ezvote.util.Utility;
import org.ezvote.util.WorkSet;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/**
 * The Voter core class
 * @author Red
 */
public class Voter {
	///log
	private static Logger _log = Logger.getLogger(Voter.class);
	
	///Strings used	
	private final static String PROP_USEBC = "useBC";
	private final static String PROP_STORE_FILE = "keystore";
	private final static String PROP_UI_TYPE = "uiType";
	private final static String PROP_LISTENPORT = "listenPort"; //the port voter listens on
		private final static String UI_TYPE_CONSOLE = "console";
		private final static String UI_TYPE_SWT = "swt";
	
	private final static String YES = "YES";
	private final static String NO = "NO";
	
	private final static String KEY_ALIAS = "Alpha"; //the key alias in keystore
	
	public final static String VOTEREG = "VoteReg";
	public final static String RESPONSE = "Response";
		public final static String RESPONSE_ID = "Id";
		public final static String RESPONSE_LISTEN = "Listen";
		public final static String RESPONSE_SIG = "Sig";
	
	private static String KEYSTORE_FORMAT = null;	
	
	///package-visible variables
	Properties _prop;
	InetSocketAddress _localListen; //the address voter listen on
	VoterUI _ui;
	SSLContext _sslCtx;	
	PrivateKey _priKey; //user's private key
	String _userId; //user's id (corresponding to private key)
	String _sessionId; //vote-session-specific id
	ServerSocket _server; //server socket
	
	PublicKey _mgrPubKey; //manager's public key
//	String _mgrId; //manager's id
	ManagerInfo _mgrInfo;
	
	Vector<AuthorityInfo> _authoritiesInfo;
//	Vector<VoterInfo> _votersInfo;
	
	PublicKey _castPubkey = null; //the pubkey used to encrypt ballot
	Date _deadline = null; //the vote-casting deadline
	
	Dispatcher _disp; //tag->work dispatcher
	
	
	///////////////////////////////////////////////////////////
	// public methods
	public Voter(Properties prop){
		_prop = prop;
		_authoritiesInfo = new Vector<AuthorityInfo>();
//		_votersInfo = new Vector<VoterInfo>();
	}
	
	/**
	 * add provider if decided to use BC;
	 * init keystore;
	 * prepare UI;
	 * @throws ConfigException 
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyManagementException 
	 * @throws UnrecoverableEntryException 
	 * @throws DispatcherException 
	 */
	public void init() throws ConfigException, KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyManagementException, UnrecoverableEntryException, DispatcherException{
		///init Dispatcher and workset
		WorkSet voterWork = new VoterWork(this);
		_disp = new Dispatcher();		
		_disp.addWorkSet(voterWork);
		
		///keystore
		String keystoreFile = _prop.getProperty(PROP_STORE_FILE);
		if( null == keystoreFile ) 
			throw new ConfigException("Failed to get store file location");
		
		///local listen address
		String port = _prop.getProperty(PROP_LISTENPORT);
		InetAddress local = InetAddress.getLocalHost();
		_localListen = new InetSocketAddress(local, Integer.parseInt(port));
		
		///UI
		String uiType = _prop.getProperty(PROP_UI_TYPE);
		if(uiType.equalsIgnoreCase(UI_TYPE_CONSOLE)){
			_ui = new VoterConsoleUI(Utility.ENCODING);
		}else if(uiType.equalsIgnoreCase(UI_TYPE_SWT)){
			throw new NotImplementedException();
		}		
		char[] password = _ui.getKeystorePass(); //get password
		
		///BC provider
		String useBC = _prop.getProperty(PROP_USEBC);
		_log.info("Init: use BC provider: " + useBC);
		if(useBC.equalsIgnoreCase(YES)){			
			///add provider, and init SSLContext with BKS keystore
			if( -1 == Security.insertProviderAt(new BouncyCastleProvider(), 1)){
				throw new ConfigException("Failed to insert provider");
			}
			KEYSTORE_FORMAT = "BKS";
			initSslCtx(keystoreFile, password);
		}else if(useBC.equalsIgnoreCase(NO)){
			KEYSTORE_FORMAT = "JKS";
			throw new NotImplementedException();
		}else{
			throw new ConfigException("useBC field wrong:"+useBC);
		}		
	}

	private void initSslCtx(String keystoreFile, char[] password)
			throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException,
			KeyManagementException, UnrecoverableEntryException {
		KeyStore kstore = KeyStore.getInstance(KEYSTORE_FORMAT);
		kstore.load(new FileInputStream(keystoreFile), password);
		
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(kstore, password);
		KeyManager[] kms = kmf.getKeyManagers();
		
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(kstore);
		TrustManager[] tms = tmf.getTrustManagers();		
		
		_sslCtx = SSLContext.getInstance("TLS");
		_sslCtx.init(kms, tms, new SecureRandom());
		
		///retrieve private key and userId(email)
		KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)
			kstore.getEntry(KEY_ALIAS, new KeyStore.PasswordProtection(password));
		_priKey = entry.getPrivateKey();
		_userId = Utility.getSubjectFromCert((X509Certificate)entry.getCertificate());		
	}
	
	public static void main(String[] args){
		try{
			initLog();
			Properties prop = initProp(args);
			
			Voter voter = new Voter(prop);
			voter.init();
			voter.listen();
			
			voter.run();
		}catch(Exception ex){
			_log.fatal("Uncaught exception", ex);
		}		
	}

	/**
	 * create server socket and listen on it
	 * @throws IOException 
	 */
	private void listen() throws IOException {
		try{
			_log.info("start to create server socket");
			SSLServerSocketFactory servFac = _sslCtx.getServerSocketFactory();
			_server = servFac.createServerSocket(_localListen.getPort(), 4, _localListen.getAddress());
		}catch(IOException ex){
			_log.error("create server socket failure: " + _localListen.getAddress().getHostAddress() + ":" + _localListen.getPort());
		}
	}

	public void run() throws RegisterException {
		_log.info("start to run");
		register(); //voter register
		
		serve(); //serve the request
	}

	private void serve() {
		while(true){			
			SSLSocket soc;
			try{
				soc = (SSLSocket)_server.accept();
				Utility.logConnection(soc, _userId);
				Thread thr = new ServerThread(soc);
				thr.start();
			}catch(IOException ex){
				_log.warn("server socket accpet failure", ex);
			} catch (CertificateException ex) {
				_log.warn("server socket verification failure", ex);				
			}			
		}
	}

	private void register() throws RegisterException {
		try {
			InetSocketAddress mgrAddr = _ui.getManagerAddr();

			SSLSocketFactory socFac = _sslCtx.getSocketFactory();			

			SSLSocket soc = (SSLSocket)socFac.createSocket(mgrAddr.getAddress(), mgrAddr.getPort());
			_log.debug("Socket creation succeeded");
			
			///retrieve manager's id and public key
			_log.debug("retrieve manager's id & pubkey");
			javax.security.cert.X509Certificate cert = soc.getSession().getPeerCertificateChain()[0];
			_mgrPubKey = cert.getPublicKey();
			String mgrId = Utility.getSubjectFromPrinciple((X500Principal)cert.getSubjectDN());
			_mgrInfo = new ManagerInfo(mgrAddr, mgrId);
			
			BufferedReader socbr = new BufferedReader(new InputStreamReader(soc.getInputStream(), Utility.ENCODING));
			BufferedWriter socbw = new BufferedWriter(new OutputStreamWriter(soc.getOutputStream(), Utility.ENCODING));
			
			///voter->manager: vote_reg
			_log.info("send vote-reg");
			Document doc = new Document(new Element(VOTEREG));
			try{
				Utility.XMLDocToWriter(doc, socbw);
			}catch(IOException ex){
				_log.error("Register: write vote_reg to manager failure");
				throw ex;				
			}
			
			///manager->voter: challenge
			_log.info("got challenge");
			try {
				doc = Utility.ReaderToXMLDoc(socbr);
				_sessionId = doc.getRootElement().getTextTrim();
			} catch (JDOMException ex) {
				_log.error("Register: parse challenge failed");
				throw ex;
			} catch(IOException ex){
				_log.error("Register: parse challenge failed");
				throw ex;
			}			
			
			///voter->manager: response to challenge
			_log.info("send response");
			try{
				doc = new Document(new Element(RESPONSE));
				Element r = doc.getRootElement();
				r.addContent(new Element(RESPONSE_ID).setText(_userId));	
				r.addContent(new Element(RESPONSE_LISTEN).setText(_localListen.getAddress().getHostAddress()+":"+_localListen.getPort()));
				r.addContent(new Element(RESPONSE_SIG).setText(Utility.genSignature(_priKey, _sessionId)));
				Utility.XMLDocToWriter(doc, socbw);
			}catch(Exception ex){
				_log.error("return response to manager failure");
				throw ex;
			}
			
			///manager->voter: whether register succeeded
			_log.info("got register result");
			try{
				doc = Utility.ReaderToXMLDoc(socbr);
				Element root = doc.getRootElement();
				if(root.getTextTrim().equals(Manager.REGFAILURE)){ ///register is rejected
					Element reason = root.getChild(Manager.REGFAILURE_REASON);					
					_ui.displayVoteContent(_mgrInfo.get_id(), reason.getTextTrim(), null);
				}else if(root.getTextTrim().equals(Manager.VOTECONTENT)){ //register succeeded
					String content = root.getChild(Manager.VOTECONTENT_CONTENT).getTextTrim();
					List<Element> opts = root.getChild(Manager.VOTECONTENT_OPTIONS)
											.getChildren(Manager.VOTECONTENT_OPTIONS_OPTION);
					String[] options = new String[opts.size()];
					Iterator<Element> it = opts.iterator();
					int cnter = 0;
					while(it.hasNext()){
						options[cnter++] = it.next().getTextTrim();
					}
					_ui.displayVoteContent(_mgrInfo.get_id(), content, options);
				}
			} catch (JDOMException ex) {
				_log.error("Register: parse register result failed");
				throw ex;
			} catch(IOException ex){
				_log.error("Register: processing register result failed");
				throw ex;
			}			
			
		} catch (Exception e) {
			_log.error("failed to register to manager");
			throw new RegisterException(e);
		}
	}

	private static Properties initProp(String[] args) {
		String configFile = "voter.config";
		if(args.length >= 1){
			configFile = args[0];
		}
		Properties prop = new Properties();
		try {
			prop.load(new BufferedReader(new InputStreamReader(new FileInputStream(configFile), Utility.ENCODING)));
		} catch (IOException e) {
			_log.error("Failed to load config file: " + configFile);
		}
		return prop;
	}

	private static void initLog() {
		try{
			BufferedReader br = new BufferedReader( 
					new InputStreamReader(Voter.class.getResourceAsStream("log4j.properties"),
							Utility.ENCODING));
			Properties prop = new Properties();
			prop.load(br);
			PropertyConfigurator.configure(prop);
			_log.info("Voter init log4j succeeded");
		}catch(IOException ex){
			System.err.println("Voter init log4j failed");
		}
	}
	
	/**
	 * serve incoming request 
	 * @author Red
	 */
	private class ServerThread extends Thread{
		
		private SSLSocket _soc;
		
		private ServerThread(SSLSocket soc){
			 _soc = soc;
		}
		
		@Override
		public void run(){
			try{
				BufferedReader in = new BufferedReader(new InputStreamReader(_soc.getInputStream(), Utility.ENCODING));
				BufferedWriter out = new BufferedWriter(new OutputStreamWriter(_soc.getOutputStream(), Utility.ENCODING));
				
				Document doc = Utility.ReaderToXMLDoc(in);
				
				dispatchRequest(doc, _soc); ///serve the request
			} catch (UnsupportedEncodingException e) {
				_log.error(e);
			} catch (IOException e) {
				_log.error(e);
			} catch (JDOMException e) {
				_log.error("Failed to read xml Document from peer", e);
			} catch(Exception e){
				_log.error(e);
			}finally{
				try {
					_soc.close();
				} catch (IOException e) {
					_log.error("Failed to close connection", e);
				}
			}
		}
	}

	/**
	 * according to the document root element, serve different requests
	 * @param doc
	 * @param in
	 * @param out
	 */
	public void dispatchRequest(Document doc, SSLSocket soc) throws Exception {
		String rootElemTag = doc.getRootElement().getTextTrim();
		_log.debug("dispatchRequest:" + rootElemTag);
		_disp.dispatch(rootElemTag, doc, soc);
	}
}


