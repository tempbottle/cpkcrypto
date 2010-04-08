package org.ezvote.crypto;

public class ProofException extends Exception {

	private static final long serialVersionUID = -4105355780463159955L;
	public ProofException(Exception ex){
		super(ex);
	}
	
	public ProofException(String str){
		super(str);
	}
	
	public ProofException(String str, Exception ex){
		super(str, ex);
	}	
}
