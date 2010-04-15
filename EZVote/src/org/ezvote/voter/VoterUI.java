package org.ezvote.voter;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;

public interface VoterUI {
	/**
	 * display misc. info
	 */
	public void displayInfo(String info);
	
	/**
	 * display the vote's content: manager's id, brief, options
	 * @param mgrId manager's id
	 * @param content 
	 * @param options 
	 */
	public void displayVoteContent(String mgrId, String content, String[] options);
	
	/**
	 * display the vote result
	 * @param results TODO
	 */
	public void displayVoteResult(String[] results);
	
	/**
	 * @return the options user selects
	 */
	public List<Boolean> getBallot();
	
	/**
	 * @return the keystore password
	 */
	public char[] getKeystorePass() throws IOException;
	
	/**
	 * @return the Manager's address(IP/host:port)
	 */
	public InetSocketAddress getManagerAddr();
}
