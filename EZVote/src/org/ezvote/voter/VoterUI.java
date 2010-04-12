package org.ezvote.voter;

import java.net.InetSocketAddress;
import java.util.List;

public interface VoterUI {
	/**
	 * @return the keystore password
	 */
	public char[] getKeystorePass();
	
	/**
	 * @return the Manager's address(IP/host:port)
	 */
	public InetSocketAddress getManagerAddr();
	
	/**
	 * display the vote's content: manager's id, brief, options
	 * @param mgrId manager's id
	 * @param content 
	 * @param options 
	 */
	public void displayVoteContent(String mgrId, String content, String[] options);
	
	/**
	 * @return the options user selects
	 */
	public List<Boolean> getBallot();
	
	/**
	 * display the vote result
	 * @param results TODO
	 */
	public void displayVoteResult(String[] results);
	
	/**
	 * display misc. info
	 */
	public void displayInfo(String info);
}
