package org.ezvote.manager;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Properties;
import java.util.Random;
import java.util.TimeZone;
import java.util.Vector;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ezvote.ConfigException;
import org.ezvote.RegisterException;
import org.ezvote.authority.AuthorityInfo;
import org.ezvote.util.Dispatcher;
import org.ezvote.util.DispatcherException;
import org.ezvote.util.Utility;
import org.ezvote.util.WorkSet;
import org.ezvote.voter.VoterInfo;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class Manager {
	
	/**
	 * a timer thread used to indicate registration is end
	 */
	private class RegTimerThread extends Thread{
		private final long _seconds;
		public RegTimerThread(long seconds){
			_seconds = seconds;
		}
		
		@Override
		public void run(){
			try {
				Thread.sleep(_seconds*1000);
			} catch (InterruptedException e) {
				_log.info("RegTimerThread interrupted");
				return;
			}
			
			try {
				stopRegistration();			//indicate the registration must stop
			} catch (Exception e) {
				_log.error("stopRegistration, failed", e);				
			} 
			
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
//				BufferedWriter out = new BufferedWriter(new OutputStreamWriter(_soc.getOutputStream(), Utility.ENCODING));
				
				Document doc = Utility.ReaderToXMLDoc(in);
				
				dispatchRequest(doc, _soc); ///serve the request
			} catch (UnsupportedEncodingException e) {
				_log.error(e);
			} catch (IOException e) {
				_log.error("IOException", e);
			} catch (JDOMException e) {
				_log.error("Failed to read xml Document from peer", e);
			} catch(Exception e){
				_log.error("ServerThread exception:", e);
			}finally{
				try {
					_soc.close();
				} catch (IOException e) {
					_log.error("Failed to close connection", e);
				}
			}
		}
	}
	private class VoteTimerThread extends Thread{
		private final long _seconds;
		public VoteTimerThread(long seconds){
			_seconds = seconds;
		}
		
		@Override
		public void run(){
			try{
				Thread.sleep(_seconds*1000);
			}catch(InterruptedException e){
				_log.info("VoteTimerThread interrupted");
				return;
			}
			
			stopVoteCasting();//indicate the vote must stop
		}
	}
	private static Logger _log = Logger.getLogger(Manager.class);
	private final static String PROP_USEBC = "useBC";
	private final static String PROP_STORE_FILE = "keystore";
	private final static String PROP_UI_TYPE = "uiType";
		private final static String PROP_LISTENPORT = "listenPort"; //the port voter listens on
		private final static String PROP_AUTH_NUMBER = "authorityNumber";
		
	private final static String PROP_CURVENAME = "curveName"; //the eccurve used for authorities' public key generation	
	private final static String UI_TYPE_CONSOLE = "console";
	private final static String UI_TYPE_SWT = "swt";

	private static String KEYSTORE_FORMAT = null;
	
	private final static String YES = "YES";
	
	private final static String NO = "NO";
		private final static String KEY_ALIAS = "Alpha"; //the key alias in keystore
	public static final String CHALLENGE = "Challenge";
		public static final String REGFAILURE = "RegFailure";
		public static final String REGFAILURE_REASON = "Reason";
		public static final String VOTECONTENT = "VoteContent";
			public static final String VOTECONTENT_SESSIONID = "SessionId";
		public static final String VOTECONTENT_CONTENT = "Content";
	
	public static final String VOTECONTENT_OPTIONS = "Options";
		public static final String VOTECONTENT_OPTIONS_OPTION = "Option";
			public static final String VOTECONTENT_SIG = "Sig";
				public static final String UPGRADE = "Upgrade";
		public static final String UPGRADE_BULLETINS = "Bulletins";
			public static final String UPGRADE_BULLETINS_ADDR = "Addr";
				public static final String UPGRADE_BULLETINS_ADDR_ID = "Id";
		public static final String UPGRADE_VOTERS = "Voters";
		public static final String UPGRADE_VOTERS_ADDR = "Addr";

	public static final String UPGRADE_VOTERS_ADDR_ID = "Id";
	
	public static final String UPGRADE_CURVENAME = "CurveName";
	
	public static final String UPGRADE_SIG = "Sig";
		public static final String STARTGENPUBKEY = "StartGenPubKey";
		
	public static final String VOTEEND = "VoteEnd";
	public static final String DISTVOTESTART = "DistVoteStart";
	public static final String DISTVOTESTART_VOTESTART = "VoteStart"; 
	private static void initLog() {
		try{
			BufferedReader br = new BufferedReader( 
					new InputStreamReader(Manager.class.getResourceAsStream("log4j.properties"),
							Utility.ENCODING));
			Properties prop = new Properties();
			prop.load(br);
			PropertyConfigurator.configure(prop);
			_log.info("Voter init log4j succeeded");
		}catch(IOException ex){
			System.err.println("Voter init log4j failed");
		}
	} 
	
	private static Properties initProp(String[] args) throws IOException {
		String configFile = "manager.config";
		if(args.length >= 1){
			configFile = args[0];
		}
		Properties prop = new Properties();
		try {
			prop.load(new BufferedReader(new InputStreamReader(new FileInputStream(configFile), Utility.ENCODING)));
		} catch (IOException e) {
			_log.error("Failed to load config file: " + configFile);
			throw e;
		}
		return prop;
	}
	
	public static void main(String[] args){
		try{
			initLog();
			Properties prop = initProp(args);
			
			Manager manager = new Manager(prop);
			manager.init();
			manager.listen();
			
			manager.run();
		}catch(Exception ex){
			_log.fatal("Uncaught exception", ex);
		}		
	}
	///package-visible variables
	Properties _prop; //config info for Manager
	ManagerInfo _self; //manager info

	ManagerUI _ui;

	SSLContext _sslCtx;
	Date _deadline = null;
	Dispatcher _disp = null;
	
	
	Vector<AuthorityInfo> _authorities = null;
	Vector<VoterInfo> _voters = null;
	PrivateKey _priKey = null;
	
	SSLServerSocket _server;
	
	VoteContent _voteContent; //vote content(brief, options, sig)
	
	EligibilityRule _eliRule; //judge whether an id is eligible

	///state
	private boolean _bRunRegistration = true; //registration is running

	private boolean _bRunVoting = true; //voting is running	
	
	private boolean _bStopServing = false; //indicate whether stop serving incoming req
	
	public Manager(Properties prop){
		_prop = prop;
		_authorities = new Vector<AuthorityInfo>();
		_voters = new Vector<VoterInfo>();
	}
	
	/**
	 * according to the document root element, serve different requests
	 * @param doc
	 * @param in
	 * @param out
	 */
	public void dispatchRequest(Document doc, SSLSocket soc) throws Exception {
		String rootElemTag = doc.getRootElement().getName();
		_log.debug("dispatchRequest:" + rootElemTag);
		_disp.dispatch(rootElemTag, doc, soc);
	}
	
	public void init() throws ConfigException, KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyManagementException, UnrecoverableEntryException, DispatcherException{
		_log.info("init() start");
		///init Dispatcher and workset
		WorkSet mgrWork = new ManagerWork(this);
		_disp = new Dispatcher();		
		_disp.addWorkSet(mgrWork);
		
		///keystore		
		String keystoreFile = _prop.getProperty(PROP_STORE_FILE);
		if( null == keystoreFile ) 
			throw new ConfigException("Failed to get store file location");
		
		///local listen address		
		String port = _prop.getProperty(PROP_LISTENPORT);
		InetAddress local = InetAddress.getLocalHost();
		InetSocketAddress socAddr = new InetSocketAddress(local, Integer.parseInt(port));
		
		///UI
		String uiType = _prop.getProperty(PROP_UI_TYPE);
		if(uiType.equalsIgnoreCase(UI_TYPE_CONSOLE)){
			_ui = new ManagerConsoleUI(Utility.ENCODING);
		}else if(uiType.equalsIgnoreCase(UI_TYPE_SWT)){
			throw new NotImplementedException();
		}		
		
		char[] password = _ui.getKeystorePass(); //get password
		
		///BC provider
		_log.info("init security provider & SSLCtx");
		String useBC = _prop.getProperty(PROP_USEBC);
		_log.info("Init: use BC provider: " + useBC);
		if(useBC.equalsIgnoreCase(YES)){			
			///add provider, and init SSLContext with BKS keystore
			if( -1 == Security.insertProviderAt(new BouncyCastleProvider(), 1)){
				throw new ConfigException("Failed to insert provider");
			}
			KEYSTORE_FORMAT = "BKS";
			String id = initSslCtx(keystoreFile, password);
			_self = new ManagerInfo(socAddr, id);
		}else if(useBC.equalsIgnoreCase(NO)){
			KEYSTORE_FORMAT = "JKS";
			throw new NotImplementedException();
		}else{
			throw new ConfigException("useBC field wrong:"+useBC);
		}		
	}
	
	private String initSslCtx(String keystoreFile, char[] password)
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
		String mgrId = Utility.getSubjectFromCert((X509Certificate)entry.getCertificate());
		
		return mgrId;
	}
	
	public boolean isRegOpen(){return _bRunRegistration;}
	
	public boolean isVoteOpen(){return _bRunVoting;}
	
	/**
	 * create server socket and listen on it
	 * @throws IOException 
	 */
	private void listen() throws IOException {
		try{
			_log.info("start to create server socket: " + _self.get_addr().toString());
			SSLServerSocketFactory servFac = _sslCtx.getServerSocketFactory();
			_server = (SSLServerSocket) servFac.createServerSocket(_self.get_addr().getPort(), 4, _self.get_addr().getAddress());
			_server.setSoTimeout(10000);// accept unblock every 5 secs
			((SSLServerSocket)_server).setNeedClientAuth(true); //require client auth
		}catch(IOException ex){
			_log.error("create server socket failure: " + _self.get_addr().getAddress().getHostAddress() + ":" + _self.get_addr().getPort());
		}
	}	
	/**
	 * init VoteContent;
	 * specify who's eligible;
	 * specify deadline 
	 * set two timer for registration and vote-casting
	 * 
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 */
	private void prepare() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
		///init VoteContent first
		_log.info("Manager: prepare start");
		Vector<String> briefAndOptions = _ui.getContentAndOptions();
		String brief = briefAndOptions.remove(0);
		Vector<String> options = briefAndOptions;		
		
		String sessionId = String.valueOf(new Random().nextLong());
		
		_voteContent = new VoteContent();
		_voteContent.init(sessionId, brief, options.toArray(new String[0]), _priKey);
				
		Date deadline = _ui.getDeadline();
		_voteContent.set_deadline(deadline);
		
		Date regDeadline = _ui.getRegDeadline();
		_voteContent.set_regDeadline(regDeadline);
		
		_eliRule = _ui.getEligibleRule();		
		
		///set timers
		Calendar c = Calendar.getInstance(TimeZone.getTimeZone(Utility.TIMEZONE_STR));
		long seconds = (regDeadline.getTime() - c.getTime().getTime())/1000;
		Thread rtt = new RegTimerThread(seconds);
		rtt.setDaemon(true);
		rtt.start();
		
		seconds = (deadline.getTime() - c.getTime().getTime()) / 1000;
		Thread vtt = new VoteTimerThread(seconds);
		vtt.setDaemon(true);
		vtt.start();
	}
	
	public void run() throws RegisterException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
		_log.info("start to run");
		prepare(); //prepare vote brief, options, eligibility, deadline
		
		serve(); //serve the incoming request
	}
	
	private void serve() {
		_log.info("ready to serve incoming connections");
		while(true){			
			SSLSocket soc;
			try{				
				soc = (SSLSocket)_server.accept();
				Utility.logInConnection(soc, _self.get_id()); //log connection
				Thread thr = new ServerThread(soc);
				thr.start();
			}catch(SocketTimeoutException e){
				if(_bStopServing){
					_log.info("Server stop serving...");
					break;
				}
			}catch(IOException ex){
				_log.warn("server socket accpet failure", ex);
			}catch (CertificateException ex) {
				_log.warn("server socket verification failure", ex);				
			}			
		}
	}
	
	/**
	 * stop registration,
	 * choose some voters to upgrade to Bulletin, send `Upgrade' to them,
	 * and send `StartGenPubKey' to bulletins
	 * @throws UnsupportedEncodingException 
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	private void stopRegistration() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException{
		_bRunRegistration = false;
		_log.info("stop Registration");
		int authNum = Integer.parseInt(_prop.getProperty(PROP_AUTH_NUMBER));
		//TODO : use some digest alg to determine which voter to be authority
		if(authNum > _voters.size()){
			_log.warn("We didn't got enough voters involved");
			_bStopServing = true;
			return;
		}
		for(int i=0; i<authNum; ++i){
			VoterInfo vi = _voters.get(i);
			_log.debug("Promote: " + vi.get_id());
			_authorities.add(new AuthorityInfo(vi.get_addr(), vi.get_id()));
		}
		
		///send `Upgrade' to these to-be-authorities
		Document upgradeDoc = new Document(new Element(Manager.UPGRADE));
		Element upRoot = upgradeDoc.getRootElement();
		Element eBuls = new Element(Manager.UPGRADE_BULLETINS);		
		for(int i=0; i<authNum; ++i){
			AuthorityInfo ainfo = _authorities.get(i);
			Element eAddr = new Element(Manager.UPGRADE_BULLETINS_ADDR);
			eAddr.setAttribute(Manager.UPGRADE_BULLETINS_ADDR_ID, ainfo.get_authId());
			eAddr.setText(ainfo.get_addr().toString());
			eBuls.addContent(eAddr);
		}
		upRoot.addContent(eBuls);
		Element eVoters = new Element(Manager.UPGRADE_VOTERS);
		for(int i=0; i<_voters.size(); ++i){
			VoterInfo vinfo = _voters.get(i);
			Element eAddr = new Element(Manager.UPGRADE_VOTERS_ADDR);
			eAddr.setAttribute(Manager.UPGRADE_BULLETINS_ADDR_ID, vinfo.get_id());
			eAddr.setText(vinfo.get_addr().toString());
			eVoters.addContent(eAddr);
		}
		upRoot.addContent(eVoters);
		Element eCurve = new Element(Manager.UPGRADE_CURVENAME);
		eCurve.setText(_prop.getProperty(Manager.PROP_CURVENAME));
		upRoot.addContent(eCurve);
		
		//create sig
		String serialXML = Utility.XMLElemToString(eBuls, eVoters, eCurve);
		String sig64 = Utility.genSignature(_priKey, serialXML);
		Element eSig = new Element(Manager.UPGRADE_SIG);
		eSig.setText(sig64);		
		upRoot.addContent(eSig);
		///create `Upgrade' doc,,,done
		
		///send doc to authorities, [sync way]
		for(AuthorityInfo ainfo : _authorities){
			Utility.syncSendXMLDocToPeer(upgradeDoc, _self.get_id(),
					ainfo.get_addr(), ainfo.get_authId(), _sslCtx);
		}
		
		///send `StartGenPubKey' to authorities
		Document startDoc = new Document(new Element(Manager.STARTGENPUBKEY));
		for(AuthorityInfo ainfo : _authorities){
			Utility.sendXMLDocToPeer(startDoc, _self.get_id(),
					ainfo.get_addr(), ainfo.get_authId(), _sslCtx);
		}
	}
	
	/**
	 * stop vote casting,
	 * send `VoteEnd' to bulletins
	 */
	private void stopVoteCasting(){
		_bRunVoting = false;
		
		_log.info("stop VoteCasting");
		Document docEnd = new Document(new Element(Manager.VOTEEND));
		for(AuthorityInfo ainfo : _authorities){
			Utility.sendXMLDocToPeer(docEnd, _self.get_id(),
					ainfo.get_addr(), ainfo.get_authId(), _sslCtx);
		}
	}
}
