/**
 * 
 */
package org.cpk.crypto.secmatrix;

/**
 * Because the GAE(Google App Engine) doesn't support add BC as provider,
 * I have to use this class to indicate Sec/Pub matrix whether use BC lightweight api
 */
public class BCSetting {
	private final boolean  m_bUseBCProvider; //true -- use BC provider; false -- use BC lightweight api
	private static BCSetting m_instance = null;
	
	public static synchronized BCSetting getInstance(boolean bUseBCprovider){
		if( m_instance == null ){
			m_instance = new BCSetting(bUseBCprovider);			
		}
		return m_instance;
	}
	public static BCSetting getInstance(){
		return getInstance(true); //default, we use BC provider
	} 
	
	BCSetting(boolean bUseBCProvider){
		m_bUseBCProvider = bUseBCProvider;
	}
	
	public boolean IsUseBCProvider(){return m_bUseBCProvider;} 
}
