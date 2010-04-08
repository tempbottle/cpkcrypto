package org.ezvote.voter;

import java.net.InetSocketAddress;

public class VoterInfo {
	private InetSocketAddress _addr;
	private String _id;
	
	public VoterInfo(InetSocketAddress addr, String id){
		_addr = addr;
		_id = id;
	}

	public InetSocketAddress get_addr() {	return _addr; 	}
	public String get_id() { return _id; }
}
