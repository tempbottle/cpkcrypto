package org.ezvote.authority;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Hashtable;
import java.util.Vector;

import javax.net.ssl.SSLContext;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.ezvote.crypto.CipherText;
import org.ezvote.manager.ManagerInfo;
import org.ezvote.voter.VoterInfo;

public class Authority {
	///the strings used
	
	public static final String VOTESTART = "VoteStart";
		public static final String VOTESTART_CURVENAME = "CurveName";
		public static final String VOTESTART_PUBKEY = "PubKey"; 
		public static final String VOTESTART_DEADLINE = "Deadline";
		public static final String VOTESTART_BULLETINS = "Bulletins";
			public static final String VOTESTART_BULLETINS_ADDR = "Addr";
				public static final String VOTESTART_BULLETINS_ADDR_ID = "Id";
		public static final String VOTESTART_SIG = "Sig";
	
	public static final String GENPUBKEY = "GenPubKey";
		public static final String GENPUBKEY_ID = "Id";
		public static final String GENPUBKEY_FACTOR = "Factor";
		public static final String GENPUBKEY_SIG = "Sig";
		
	public static final String GENPUBKEYFINISH = "GenPubKeyFinish";
		public static final String GENPUBKEYFINISH_PUBKEY = "PubKey";
		
	public static final String PUBFACTOR = "PubFactor";
		public static final String PUBFACTOR_WITNESS = "Witness";
		public static final String PUBFACTOR_PROOF = "Proof";
		
	public static final String RESULT = "Result";
		public static final String RESULT_OPTION = "Option";
			public static final String RESULT_OPTION_COUNT = "Count";
		
	///package-visible variables
	VoterInfo _selfVoter; //the info of voter self
	ManagerInfo _mgrInfo; //the info of manager
	Vector<AuthorityInfo> _authoritiesInfo; //all authorities' info
	Vector<VoterInfo> _votersInfo; //all voters' info
	PrivateKey _priKey; //the private key of voter
	SSLContext _sslCtx;
	
	BigInteger _secretShare; 
	ECPoint _publicShare;
	ECPoint _sumPubShare; //the sum of public share, will be the public key used to encrypt ballot
	Hashtable<String, ECPoint> _shareTable; //<authId, pubShare> map
	ECParameterSpec _ecParam; //the EC parameter used for keygen for ballot enc/dec
	Vector<CipherText> _tally = null;
	Result _result = null;
	
	public Authority(SSLContext sslctx, 
			PrivateKey priKey, 
			VoterInfo self, 
			ManagerInfo mgr,
			String curveName
			) throws IOException{
		_sslCtx = sslctx;
		_priKey = priKey;
		_selfVoter = self;
		_mgrInfo = mgr;
		_authoritiesInfo = new Vector<AuthorityInfo>();
		_votersInfo = new Vector<VoterInfo>();
		_ecParam = ECNamedCurveTable.getParameterSpec(curveName);
		assert(_sslCtx!=null && _priKey!=null && _selfVoter!=null && _mgrInfo!=null);
		_shareTable = new Hashtable<String, ECPoint>();
		
		if( null == _ecParam ){
			throw new IOException("the curve name not available: " + curveName);
		}
	}
	
	public Vector<AuthorityInfo> get_authoritiesInfo() {return _authoritiesInfo;}
	public Vector<VoterInfo> get_votersInfo() {return _votersInfo;}
}
