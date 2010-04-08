package org.ezvote;

public class ConfigException extends Exception {

	private static final long serialVersionUID = 7868088192106188099L;

	public ConfigException(Exception ex){
		super(ex);
	}
	
	public ConfigException(String str){
		super(str);
	}
	
	public ConfigException(String str, Exception ex){
		super(str, ex);
	}	
}
