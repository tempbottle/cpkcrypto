package org.ezvote.voter;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

/**
 * console ui for voter 
 * @author Red
 */
class VoterConsoleUI implements VoterUI {
	
	private static Logger _log = Logger.getLogger(VoterConsoleUI.class);
	
	private BufferedReader _br;
	private String[] _options;
	
	VoterConsoleUI(String encoding) throws UnsupportedEncodingException{
		_br = new BufferedReader(new InputStreamReader(System.in, encoding));
	}
	
	@Override
	public char[] getKeystorePass() {
		System.out.println("Please input the keystore password:");
		Console con = System.console();
		char[] password = con.readPassword();
		return password;
	}
	
	@Override
	public InetSocketAddress getManagerAddr() {
		System.out.println("Please input the Manager's address [in IP:port format]:");
		InetSocketAddress addr;
		do{
			try {
				String line = _br.readLine();
				String[] parts = line.split(":");
				int port = Integer.parseInt(parts[1]);
				addr = new InetSocketAddress(parts[0], port);
				break;
			} catch (IOException e) {
				System.out.println("It seems that your input is invalid, please input again");
				_log.error("error during getManagerAddr", e);
			}
		}while(true);
		
		return addr;
	}

	@Override
	public void displayVoteContent(String mgrId, String content, String[] options) {
		System.out.println("Below are content provided by Manager:" + mgrId);
		System.out.println(content);
		System.out.println();
		System.out.println("Below are options:");
		_options = options;
		if(_options == null){
			System.out.println("No options available");
			return;
		}
		int cnter = 0;
		for(String op : options){			
			System.out.println(++cnter +": "+ op);
		}
		
	}
	
	@Override
	public List<Boolean> getBallot() {
		System.out.println("Please input your choice(s): (space separated)");
		List<Boolean> lst = new ArrayList<Boolean>();
		do{
			try{
				String line = _br.readLine();
				String[] choices = line.split("\\s");
				System.out.println("Your choices are:");
				for(String c : choices){
					int choice = Integer.parseInt(c);
					lst.set(choice-1, true);
					System.out.println(choice+": "+_options[choice-1]);
				}
				System.out.println("Is this correct?(Y/N)");
				String answer = _br.readLine();
				if(answer.startsWith("Y")){
					break;
				}else{
					System.out.println("You reverted your choices: Please input again:");
				}				
			}catch(Exception ex){
				System.out.println("Failed to parse your choice: please input again");
			}
		}while(true);
		
		return lst;
	}

	@Override
	public void displayVoteResult(String[] results) {
		System.out.println("The Vote results are published:");
		assert(results.length == _options.length);
		for(int i=1; i<=_options.length; ++i){
			System.out.println(_options[i] + " : " + results[i-1]);
		}
		System.out.println("Vote completed");
	}
}
