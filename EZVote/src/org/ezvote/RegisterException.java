package org.ezvote;

public class RegisterException extends Exception {

	private static final long serialVersionUID = 2933120496078905617L;

	public RegisterException(String str){
		super(str);
	}
	
	public RegisterException(String str, Exception ex){
		super(str, ex);
	}	
	
	public RegisterException(Exception ex){
		super(ex);
	}
}
