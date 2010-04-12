package org.ezvote.authority;

public class TallyException extends Exception {

	private static final long serialVersionUID = 5093771434458871073L;

	public TallyException(Exception ex){
		super(ex);
	}
	
	public TallyException(String str){
		super(str);
	}
	
	public TallyException(String str, Exception ex){
		super(str, ex);
	}	
}
