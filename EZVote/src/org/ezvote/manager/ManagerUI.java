package org.ezvote.manager;

import java.io.IOException;
import java.util.Date;
import java.util.Vector;

public interface ManagerUI {

	/**
	 * get brief and options 
	 * @throws IOException 
	 */
	Vector<String> getContentAndOptions() throws IOException;
	
	/**
	 * get the vote-casting deadline
	 * @throws IOException 
	 */
	Date getDeadline() throws IOException;  
	
	/**
	 * get the rule that specify who's eligible to participate vote
	 * @throws IOException 
	 */
	EligibilityRule getEligibleRule() throws IOException;
	
	/**
	 * get Keystore's password	 
	 */
	char[] getKeystorePass() throws IOException;
	
	/**
	 * get the deadline for registration 
	 * @throws IOException 
	 */
	Date getRegDeadline() throws IOException;
}
