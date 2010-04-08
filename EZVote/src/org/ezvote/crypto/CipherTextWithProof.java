package org.ezvote.crypto;

public class CipherTextWithProof {
	public CipherText _ct;
	public VoteProof _vp;
	
	public CipherTextWithProof(CipherText ct, VoteProof vp){
		_ct = ct; _vp = vp;
	}
	
	public CipherText get_ct() {
		return _ct;
	}
	public VoteProof get_vp() {
		return _vp;
	}
	
}
