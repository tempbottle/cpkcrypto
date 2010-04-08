package org.ezvote.authority;

import java.net.InetSocketAddress;

public class AuthorityInfo {
	InetSocketAddress _addr; //the addr&port authority listens on
	String _authId; //the authority's id	
	
	public AuthorityInfo(InetSocketAddress addr, String id){
		_addr = addr; _authId = id;
	}
	
	public InetSocketAddress get_addr() {return _addr;}
	public String get_authId() {return _authId;}	
}
