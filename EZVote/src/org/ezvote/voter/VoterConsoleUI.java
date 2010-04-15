package org.ezvote.voter;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.ezvote.util.Utility;

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
	public void displayInfo(String info){
		System.out.println("Message Coming in:");
		System.out.println("\t"+info);
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
	public void displayVoteResult(String[] results) {
		System.out.println("The Vote results are published:");
		assert(results.length == _options.length);
		for(int i=0; i<_options.length; ++i){
			System.out.println(results[i]);
		}
		System.out.println("Vote completed");
	}
	
	@Override
	public boolean[] getBallot() {
		System.out.println("Please input your choice(s): (space separated)");
		boolean[] lst = new boolean[_options.length];
		do{
			try{
				String line = _br.readLine();
				String[] choices = line.split("\\s");
				System.out.println("Your choices are:");
				for(String c : choices){
					int choice = Integer.parseInt(c);
					lst[choice-1]= true;
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
	public char[] getKeystorePass() throws IOException {
		System.out.println("Please input the keystore password:");
		return Utility.getPasswordFromConsole(_br);
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
}
