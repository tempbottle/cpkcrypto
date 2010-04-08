package org.ezvote.util;

public class DispatcherException extends Exception {

	private static final long serialVersionUID = -7725192077330335844L;

	public DispatcherException(Exception ex){
		super(ex);
	}
	
	public DispatcherException(String str){
		super(str);
	}
	
	public DispatcherException(String str, Exception ex){
		super(str, ex);
	}	
}
