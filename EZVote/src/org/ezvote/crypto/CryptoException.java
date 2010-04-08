package org.ezvote.crypto;

public class CryptoException extends Exception {

	private static final long serialVersionUID = 2563131040640453481L;

	public CryptoException(Exception ex){
		super(ex);
	}
	
	public CryptoException(String str){
		super(str);
	}
	
	public CryptoException(String str, Exception ex){
		super(str, ex);
	}	
}
