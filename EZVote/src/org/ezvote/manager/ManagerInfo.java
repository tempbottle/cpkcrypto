package org.ezvote.manager;

import java.net.InetSocketAddress;

public class ManagerInfo {
	private String _id;
	private InetSocketAddress _addr;
	
	public ManagerInfo(InetSocketAddress addr, String id){
		_addr = addr; _id = id;
	}

	public InetSocketAddress get_addr() {return _addr;}
	public String get_id() {return _id;}
	
}
