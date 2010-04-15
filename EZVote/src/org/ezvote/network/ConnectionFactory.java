package org.ezvote.network;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.log4j.Logger;
import org.ezvote.ConfigException;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;


public class ConnectionFactory {

	private static Logger log = Logger.getLogger(ConnectionFactory.class);
	///connection types available:
	public static final int CONNTYPE_JCE_BKS_TLS = 1;
	public static final int CONNTYPE_BC_TLS = 2;
	
	private SSLContext _sslContext = null;
	
	/**
	 * init the factory with keystore/truststore 
	 * @param type the connection type prefered
	 * @param keystore
	 * @param truststore
	 */
	public ConnectionFactory(String keystore, String truststore, char[] pass, int type) throws ConfigException{
		log.info("ConnectionFactory init: keystore:"+keystore+"; trustStore:"+truststore+"; type="+type);
		try{
			switch(type){
			case CONNTYPE_JCE_BKS_TLS:
				initJCETLS(keystore, truststore, pass); break;
			case CONNTYPE_BC_TLS:
				initBCTLS(keystore, truststore, pass); break;
			default:
				log.error("invalid connection factory type:"+type);
				throw new ConfigException("invalid factory type");
			}
		}catch(Exception ex){
			log.fatal("ConnectionFactory init failure", ex);
			throw new ConfigException("ConnectionFactory init failure", ex);
		}
	}
	
	public Connection createConn(String address){
		throw new NotImplementedException();
	}

	private void initBCTLS(String keystore, String truststore, char[] pass) {
		throw new NotImplementedException();
	}
	
	private void initJCETLS(String keystore, String truststore, char[] pass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, KeyManagementException {
		
		log.info("init JCE TLS");
		KeyStore ks = KeyStore.getInstance("BKS");
		InputStream ksis = new FileInputStream(keystore);
		ks.load(ksis, pass);
		// init trust manager factory
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(ks);
		TrustManager[] tms = tmf.getTrustManagers();
		// init key manager factory
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(ks, pass);
		KeyManager[] kms = kmf.getKeyManagers();
		
		//init ssl context
		_sslContext = SSLContext.getInstance("TLS");
		_sslContext.init(kms, tms, new SecureRandom());
		
		log.info("init JCE TLS...done");
	}
}
