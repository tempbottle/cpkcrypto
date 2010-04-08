package org.ezvote;

public class SignatureException extends Exception {

	private static final long serialVersionUID = -8880961670647844902L;

	public SignatureException(String str){
		super(str);
	}
	
	public SignatureException(String str, Exception ex){
		super(str, ex);
	}	
	
	public SignatureException(Exception ex){
		super(ex);
	}
}
