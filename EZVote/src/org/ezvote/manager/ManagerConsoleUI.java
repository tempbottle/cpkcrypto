package org.ezvote.manager;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.ezvote.util.Utility;

public class ManagerConsoleUI implements ManagerUI {
	
	private static Logger _log = Logger.getLogger(ManagerConsoleUI.class);
	
	final String _encoding; 

	public ManagerConsoleUI(String encoding) {
		_encoding = encoding;
	}
	
	@Override
	public char[] getKeystorePass() {
		System.out.println("Please input the keystore password:");
		Console con = System.console();
		char[] password = con.readPassword();
		return password;
	}

	@Override
	public Vector<String> getContentAndOptions(){
		try{
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in, _encoding));
			System.out.println("Please input some brief description for this vote:" +
				"(use double `enter' to end input)");
			
			StringBuilder bdr = new StringBuilder();
			String line = null;
			while(null != (line = br.readLine()) && line.length() != 0){
				bdr.append(line);
			}
			
			Vector<String> ret = new Vector<String>();
			ret.add(bdr.toString());
			
			System.out.println("Please input options: (one line for one option," +
					" double `enter to end input) ");
			while(null != (line = br.readLine()) && line.length() != 0){
				ret.add(line);
			}
			
			return ret;
		}catch(Exception e){
			_log.error("Failed to get ContentAndOptions");
			System.err.println("SOMETHING WRONG happended");
			return null;
		}
	}

	@Override
	public Date getDeadline() {
		String line = null;
		try{
			System.out.println("Please input time duration for this vote:(in minutes)");
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in, _encoding));
			line = br.readLine();
			int minutes = Integer.getInteger(line);
			Calendar c = Calendar.getInstance(TimeZone.getTimeZone(Utility.TIMEZONE_STR));
			c.add(Calendar.MINUTE, minutes);
			
			return c.getTime();
		}catch(Exception e){
			_log.error("Failed to get Deadline: "+line);
			System.err.println("SOMETHING WRONG HAPPENED");
			return null;
		}		
	}

	@Override
	public EligibilityRule getEligibleRule() {
		System.out.println("Please specify the rule of eligibility:");
		try{
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in, _encoding));
			String line = br.readLine();
			return new RegexRule(line);
		}catch(Exception e){
			_log.error("Failed to get Eligibility rule");
			System.err.println("SOMETHING WRONG HAPPENED");
			return null;
		}
		
	}

}
