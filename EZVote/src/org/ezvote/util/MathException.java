package org.ezvote.util;

public class MathException extends Exception {
	
	private static final long serialVersionUID = -2897320557787642045L;

	public MathException(Exception ex){
		super(ex);
	}
	
	public MathException(String str){
		super(str);
	}
	
	public MathException(String str, Exception ex){
		super(str, ex);
	}	
}
