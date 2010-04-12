package org.ezvote.manager;

import java.util.Date;
import java.util.Vector;

public interface ManagerUI {

	/**
	 * get Keystore's password	 
	 */
	char[] getKeystorePass();
	
	/**
	 * get brief and options 
	 */
	Vector<String> getContentAndOptions();  
	
	/**
	 * get the vote-casting deadline
	 */
	Date getDeadline();
	
	/**
	 * get the rule that specify who's eligible to participate vote
	 */
	EligibilityRule getEligibleRule();
}
