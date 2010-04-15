package org.ezvote.manager;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.ezvote.util.Utility;

public class ManagerConsoleUI implements ManagerUI {
	
	private static Logger _log = Logger.getLogger(ManagerConsoleUI.class);
	private final BufferedReader _br;
	
	final String _encoding; 

	public ManagerConsoleUI(String encoding) throws UnsupportedEncodingException {
		_encoding = encoding;
		_br = new BufferedReader(new InputStreamReader(System.in, _encoding));
	}
	
	@Override
	public Vector<String> getContentAndOptions() throws IOException{
		try{
			System.out.println("Please input some brief description for this vote:" +
				"(use double `enter' to end input)");
			
			StringBuilder bdr = new StringBuilder();
			String line = null;
			while(null != (line = _br.readLine()) && line.length() != 0){
				bdr.append(line);
			}
			
			Vector<String> ret = new Vector<String>();
			ret.add(bdr.toString());
			_log.debug("description="+bdr.toString());
			
			System.out.println("Please input options: (one line for one option," +
					" double `enter to end input) ");
			while(null != (line = _br.readLine()) && line.length() != 0){
				ret.add(line);
				_log.debug("option= "+line);
			}
			
			return ret;
		}catch(IOException e){
			_log.error("Failed to get ContentAndOptions");
			System.err.println("SOMETHING WRONG happended");
			throw e;
		}
	}
	
	@Override
	public Date getDeadline() throws IOException{
		try{
			System.out.println("Please input time duration for this vote:(in minutes)");			
			String line = _br.readLine();
			_log.debug("deadLine: " + line);
			int minutes = Integer.parseInt(line);
			Calendar c = Calendar.getInstance(TimeZone.getTimeZone(Utility.TIMEZONE_STR));
			c.add(Calendar.MINUTE, minutes);
			
			return c.getTime();
		}catch(IOException e){
			_log.error("Failed to get Deadline", e);
			System.err.println("SOMETHING WRONG HAPPENED");
			throw e;
		}		
	}

	@Override
	public EligibilityRule getEligibleRule() throws IOException{
		System.out.println("Please specify the rule of eligibility:");
		try{
			String line = _br.readLine();
			_log.debug("rule: "+line);
			return new RegexRule(line);
		}catch(IOException e){
			_log.error("Failed to get Eligibility rule", e);
			System.err.println("SOMETHING WRONG HAPPENED");
			throw e;
		}
		
	}

	@Override
	public char[] getKeystorePass() throws IOException {
		System.out.println("Please input the keystore password:");
		return Utility.getPasswordFromConsole(_br);
	}

	@Override
	public Date getRegDeadline() throws IOException{
		String line = null;
		try{
			System.out.println("Please input time duration for registration:(in minutes)");
			line = _br.readLine();
			_log.debug("regDeadline: "+line);
			int minutes = Integer.parseInt(line);
			Calendar c = Calendar.getInstance(TimeZone.getTimeZone(Utility.TIMEZONE_STR));
			c.add(Calendar.MINUTE, minutes);
			
			return c.getTime();
		}catch(IOException e){
			_log.error("Failed to get RegDeadline: "+line);
			System.err.println("SOMETHING WRONG HAPPENED");
			throw e;
		}		
	}

}
