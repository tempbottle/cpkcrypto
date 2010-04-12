package org.ezvote.manager;

import org.apache.log4j.Logger;
import org.ezvote.util.WorkSet;

public class ManagerWork implements WorkSet {
	
	private static Logger _log = Logger.getLogger(ManagerWork.class);
	
	private static String[] _desc = new String[]{
		"VoteReg", "procVoteReg", //note: this is a group of interaction
		"GenPubKeyFinish", "procGenPubKeyFinish"		
	};

	public ManagerWork(Manager manager) {
	}

	@Override
	public String[] getWorkDesc() {
		// TODO Auto-generated method stub
		return null;
	}

}
