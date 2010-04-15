package org.ezvote.authority;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Vector;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;
import javax.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.ezvote.crypto.CipherText;
import org.ezvote.crypto.CryptoException;
import org.ezvote.crypto.ProofException;
import org.ezvote.crypto.SecShareProof;
import org.ezvote.crypto.VoteCipher;
import org.ezvote.crypto.VoteProof;
import org.ezvote.manager.Manager;
import org.ezvote.util.MathException;
import org.ezvote.util.Utility;
import org.ezvote.util.WorkSet;
import org.ezvote.voter.Voter;
import org.ezvote.voter.VoterInfo;
import org.jdom.Document;
import org.jdom.Element;

public class AuthorityWork implements WorkSet {
	
	private static Logger _log = Logger.getLogger(AuthorityWork.class);
	
	private Authority _authority;
	private Voter _voter;
	private boolean[] _authState = null; //whether an auth sent GenPubKey 
	private AtomicInteger _gotGPKMsgCnt = new AtomicInteger(); //count received msg, for GenPubKey
	private AtomicInteger _gotPFMsgCnt = new AtomicInteger(); //count received msg, for PubFactor
	private String[] _desc = new String[]{
			"StartGenPubKey" , "procStartGenPubKey",
			"GenPubKey", "procGenPubKey",
			"DistVoteStart", "procDistVoteStart",
			"Ballot", "procBallot",
			"VoteEnd", "procVoteEnd", 
			"PubFactor", "procPubFactor" 
	};
	private boolean _isEnd = false; //whether the vote is over
	private AtomicInteger _rcvPubFactor = new AtomicInteger(); //cnter of received PubFactor msg
	private Vector<ECPoint> _cipherPrivateKey; //as long as options, the private key(ECPoint) for tally cipherText	
	
	public AuthorityWork(Authority auth, Voter voter, int authNumber){ 
		_authority = auth;
		_voter = voter;
		_cipherPrivateKey = new Vector<ECPoint>();
		int len = _voter.get_options().length;
		ECPoint infi = _authority._ecParam.getCurve().getInfinity();
		for(int i=0; i<len; ++i){
			_cipherPrivateKey.add(infi);
		}
		_authority._result = new Result(len);
		
		///init an datastructure to indicate whether an authority has send GenPubKey msg
		_authState = new boolean[authNumber];
		for(int i=0; i<_authState.length; ++i)
			_authState[i] = false;
	}	

	private int[] getStartAndLen(){
		///find which group of voter I should take care of
		int idx = 0; //the authority index	
		for(; idx < _authority._authoritiesInfo.size(); ++idx){
			if(_authority._selfVoter.get_id().
					equals(_authority._authoritiesInfo.get(idx)._authId)){
				break;
			}
		}
		
		// each authority have at least `share' voters to notify
		int share = _authority._votersInfo.size() / _authority._authoritiesInfo.size();
		int start = idx * share;
		if( idx == _authority._authoritiesInfo.size() - 1){ //last auth will process more voters
			share = _authority._authoritiesInfo.size() - idx * share;
		}
		
		return new int[]{start, share};
	}
	
	@Override
	public String[] getWorkDesc() {
		return _desc;
	}

	/**
	 * read in the ballot, 
	 * 1. verify the peer is valid voter, verify the sig
	 * 2. verify the proof is valid
	 * 3. homo add the ballot	
	 * and write back a line indicating status 
     *
	 * @throws IOException 
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws CryptoException 
	 */
	public void procBallot(Document doc, SSLSocket soc) throws CertificateException, IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, CryptoException{
		_log.debug("procBallot");
		SSLSession session = soc.getSession();
		String peerId = Utility.getSubjectFromPrinciple(session.getPeerPrincipal());
		
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(soc.getOutputStream(), Utility.ENCODING));
		
		if(_isEnd){
			_log.warn("Voting is closed: "+peerId);
//			bw.write("408 Voting is closed");
//			bw.flush();
			return;
		}		
			
		///verify voter is valid		
		PublicKey peerPubKey = session.getPeerCertificateChain()[0].getPublicKey();
		_log.debug("peerId = "+peerId);
		boolean isValidVoter = false;
		for(VoterInfo vinfo : _authority._votersInfo){
			if(vinfo.get_id().equals(peerId)){				
				isValidVoter = true;
				break;
			}
		}
		
		if( ! isValidVoter ){ //this user is not authorized to join voting
			_log.warn("the voter is not eligible: "+peerId);
//			bw.write("401 Unauthorized voter");
//			bw.flush();
			return;
		}
		
		///verify sig
		Element root = doc.getRootElement();
		Element eVote = root.getChild(Voter.BALLOT_VOTE);
		Element eProof = root.getChild(Voter.BALLOT_PROOF);
		Element eSig = root.getChild(Voter.BALLOT_SIG);
		String serialXML = Utility.XMLElemToString(eVote, eProof);
		boolean isValidSig = 
			Utility.VerifyBase64Sig(serialXML, eSig.getTextTrim(), peerPubKey);
		if( ! isValidSig ){
			_log.warn("Invalid signature from :"+peerId);
//			bw.write("400 Invalid sig");
//			bw.flush();
			return;
		}
		
		///deserial ballot
		_log.debug("deserialize cipherText");		
		byte[] bytesBallot = Base64.decodeBase64(eVote.getTextTrim());
		ASN1InputStream asnis = new ASN1InputStream(bytesBallot);
		DERSequence topseq = (DERSequence)asnis.readObject();
		ECCurve curve = _authority._ecParam.getCurve();
		Vector<CipherText> vecCipherText = new Vector<CipherText>();
		for(int i=0; i<topseq.size(); ++i){
			byte[] bytesCt = ((DERSequence)topseq.getObjectAt(i)).getDEREncoded();
			CipherText ct = CipherText.deserialize(curve, bytesCt);
			vecCipherText.add(ct);
		}		
		
		///verify proof is valid	
		_log.debug("deserialize proof");		
		byte[] bytesProof = Base64.decodeBase64(eProof.getTextTrim());
		asnis = new ASN1InputStream(bytesProof);
		topseq = (DERSequence)asnis.readObject();
		for(int i=0; i<topseq.size(); ++i){
			byte[] bytesVP = ((DERSequence)topseq.getObjectAt(i)).getDEREncoded();
			VoteProof vp = VoteProof.deserialize(_authority._ecParam, bytesVP);
			boolean isValidProof = vp.verifyProof(vecCipherText.get(i),
					_authority._ecParam, _authority._sumPubShare);
			if( ! isValidProof ){
				_log.warn("invalid proof from " + peerId);
//				bw.write("400 Invalid Proof");
//				bw.flush();
				return;
			}
		}
		
		///homo add the ballot
		_log.debug("tally this ballot");
		if(_authority._tally == null){
			_authority._tally = vecCipherText;
		}else{
			Vector<CipherText> tally = _authority._tally;
			for(int i=0; i<tally.size(); ++i){
				tally.set(i, tally.get(i).HomoAdd(vecCipherText.get(i)));
			}
		}
		_log.debug("tally this ballot...done");
	}
	
	/**
	 * get from Manager the `VoteStart' msg, broadcast it to voters 
	 */
	public void procDistVoteStart(Document doc, SSLSocket soc){
		
		_log.info("procDistVoteStart");
		
		int[] s_l = getStartAndLen();
		int start = s_l[0], share= s_l[1];
		
		final Vector<VoterInfo> voters = _authority._votersInfo;
		for(int i=start; i<start+share; ++i){ //send to each voter
			VoterInfo v = voters.get(i);
			Document newdoc = new Document((Element) doc.getRootElement().
					getChild(Manager.DISTVOTESTART_VOTESTART).detach());
			Utility.sendXMLDocToPeer(newdoc, _authority._selfVoter.get_id(),
					v.get_addr(), v.get_id(), _authority._sslCtx);
		}
				
	}
	
	/**
	 *	add this piece of pass-in public-share to sum 
	 * @throws SignatureException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws IOException 
	 */
	public void procGenPubKey(Document doc, SSLSocket soc) throws SignatureException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, IOException{
		_log.debug("procGenPubKey");
		Element root = doc.getRootElement();
		Element eId = root.getChild(Authority.GENPUBKEY_ID);
		Element eFactor = root.getChild(Authority.GENPUBKEY_FACTOR);
		String serialXML = Utility.XMLElemToString(eId, eFactor); 
		String sig64 = root.getChildTextTrim(Authority.GENPUBKEY_SIG);
		
		X509Certificate cert = soc.getSession().getPeerCertificateChain()[0];
		String peerId = Utility.getSubjectFromPrinciple(cert.getSubjectDN());
		String idInE = eId.getTextTrim();
		if( ! peerId.equals(idInE) )
			throw new CertificateException("id in msg differs from id in certificate");
		
		PublicKey peerPubKey = cert.getPublicKey(); //get the peer's pubkey
		
		try{
			if( ! Utility.VerifyBase64Sig(serialXML, sig64, peerPubKey)){
				_log.error("serialXML="+serialXML+"\nFAILED sig:"+sig64+
						"\ncorresponding pubkey: "+Base64.encodeBase64String(peerPubKey.getEncoded()));				
				throw new SignatureException("'GenPubKey' message signature verification failure");
			}
		}catch(Exception e){
			throw new SignatureException("'GenPubKey' message signature verification failure", e);
		}		
		///verify signature done
		
		///check whether this peer is authority, and whether already send this msg		
		boolean isAuthAndNew = false; 
		for(int i=0; i<_authority._authoritiesInfo.size(); ++i){
			AuthorityInfo ainfo = _authority._authoritiesInfo.get(i);
			if(ainfo._authId.equals(idInE)){
				if(! _authState[i]){ //not sent yet
					_authState[i] = true;					
					isAuthAndNew = true;
				}
				break;
			}
		}
		if( !isAuthAndNew )
			return;		
		
		///add the share to sum
		byte[] bytesPubShare = Base64.decodeBase64(eFactor.getTextTrim()); 
		ECPoint pt = new X9ECPoint(_authority._ecParam.getCurve(), 
				(ASN1OctetString)new ASN1InputStream(bytesPubShare).readObject()).getPoint();
		_authority._shareTable.put(idInE, pt); //store that auth
		_authority._sumPubShare = _authority._sumPubShare.add(pt); //sum the pass-in pub-share
		
		///if got all share, pub the generated pubkey(an ecpt) to manager, <GenPubKeyFinish>
		if(_gotGPKMsgCnt.addAndGet(1) == _authority._authoritiesInfo.size()-1){
			_gotGPKMsgCnt.set(0); //reset for PubFactor
//			//generate pubkey
//			ECPublicKeySpec pubSpec = new ECPublicKeySpec(
//					_authority._sumPubShare, _authority._ecParam);
//			KeyFactory keyFac = KeyFactory.getInstance(Utility.KEYSPEC_ALG);
//			PublicKey genPubKey = keyFac.generatePublic(pubSpec); 
			
			//transfer pubkey(an ecpt) to manager
			Document newdoc = new Document(new Element(Authority.GENPUBKEYFINISH));
			newdoc.getRootElement().addContent(
					new Element(Authority.GENPUBKEYFINISH_PUBKEY).setText(
							Base64.encodeBase64String(
							new X9ECPoint(_authority._sumPubShare).getDEREncoded())));
			Utility.sendXMLDocToPeer(newdoc, _authority._selfVoter.get_id(),
					_authority._mgrInfo.get_addr(), _authority._mgrInfo.get_id(),
					_authority._sslCtx); //send to manager			
		}
	}
	
	/**
	 * for each option i, 
	 * verify proof, add the witness to _cipherPrivateKey[i]; 
	 * sum up all private keys for each option
	 * when all the factor got, decrypt the tally and send them to voter
	 * 
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws ProofException 
	 * @throws CertificateException 
	 * @throws MathException 
	 * 
	 */
	public void procPubFactor(Document doc, SSLSocket soc) throws IOException, NoSuchAlgorithmException, ProofException, CertificateException, MathException{
		_log.debug("procPubFactor");
		Element root = doc.getRootElement();
		Element eWitness = root.getChild(Authority.PUBFACTOR_WITNESS);
		Element eProof = root.getChild(Authority.PUBFACTOR_PROOF);
		
		SSLSession session = soc.getSession();
		String peerId = Utility.getSubjectFromPrinciple(session.getPeerPrincipal());
		ECPoint Pj = _authority._shareTable.get(peerId);
		if(Pj == null){
			_log.warn("Failed to find peerId:"+peerId);
			return;
		}
				
		///deserialize witnesses
		byte[] bytesWitness = Base64.decodeBase64(eWitness.getTextTrim());		
		ASN1InputStream asnis = new ASN1InputStream(bytesWitness);
		DERSequence witnessSeq = (DERSequence)asnis.readObject();				
		Vector<ECPoint> vecW = new Vector<ECPoint>(witnessSeq.size());
		for(int i=0; i<witnessSeq.size(); ++i){
			ECPoint pt = new X9ECPoint(_authority._ecParam.getCurve(),
					(ASN1OctetString)witnessSeq.getObjectAt(i)).getPoint();
			vecW.add(pt);
		}
		
		///deserialize proofs, and verify it
		_log.debug("deserialize SecShareProof and verify it");
		byte[] bytesProof = Base64.decodeBase64(eProof.getTextTrim());
		asnis = new ASN1InputStream(bytesProof);
		DERSequence proofSeq = (DERSequence)asnis.readObject();
		
		for(int i=0; i<proofSeq.size(); ++i){
			SecShareProof ssp = SecShareProof.deserialize(
					_authority._ecParam, ((DERSequence)proofSeq.getObjectAt(i)).getDEREncoded());
			boolean isValidProof = ssp.verifyProof(
					Pj,
					vecW.get(i),
					_authority._ecParam.getG(),
					_authority._tally.get(i).getX(),
					_authority._ecParam.getN()
					);
			if(! isValidProof ){
				_log.warn("invalid proof for PubFactor: no."+i);
				throw new ProofException("Invalid proof for PubFactor");
			} 
		}
		
		_log.debug("sum up pubfactor");
		///sum up pubfactor to build private key for each option
		synchronized(_cipherPrivateKey){
			for(int i=0; i<vecW.size(); ++i){
				_cipherPrivateKey.set(i,
						_cipherPrivateKey.get(i).add(vecW.get(i)));
			}
		}
		
		///if all the factor are collected, then decrypt tally and send result to voter
		if(_gotPFMsgCnt.addAndGet(1) == _authority._authoritiesInfo.size()-1){
			_log.debug("ready to decrypt tally");			
			Vector<CipherText> tally = _authority._tally;
			String[] options = _voter.get_options();
			Result res = _authority._result;
			for(int i=0; i<options.length; ++i){				
				ECPoint clearText = 
					tally.get(i).getY().subtract(_cipherPrivateKey.get(i));
				int yescnt = Utility.findYesVoteCount(clearText, _authority._ecParam, _authority._votersInfo.size());
				res.addResult(yescnt, options[i]);
			}
			
			//create document			
			Document newdoc = new Document(new Element(Authority.RESULT));
			Element rootElem = newdoc.getRootElement();
			for(int i=0; i<options.length; ++i){
				Element op = new Element(Authority.RESULT_OPTION);
				op.setAttribute(Authority.RESULT_OPTION_COUNT, String.valueOf(res.getYesCnt(i)));
				op.setText(res.getOption(i));
				rootElem.addContent(op);
			}
			_log.debug("ready to send vote result to voters");
			//send to voters
			int[] s_l = getStartAndLen();
			int start = s_l[0], share= s_l[1];
			final Vector<VoterInfo> voters = _authority._votersInfo;
			for(int i=start; i<start+share; ++i){ //send to each voter
				VoterInfo v = voters.get(i);				
				Utility.sendXMLDocToPeer(newdoc, _authority._selfVoter.get_id(),
						v.get_addr(), v.get_id(), _authority._sslCtx);
			}
			_log.debug("send vote result to voters:done");
		}
	}
	
	/**
	 * manager notify Authority to start generate public key together
	 * send public share to other authorities	 
	 * @throws UnsupportedEncodingException 
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public void procStartGenPubKey(Document doc, SSLSocket soc) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException{
		_log.info("procStartGenPubKey");
		///generate secret share and public share
		BigInteger N = _authority._ecParam.getN();
		int bitlen = N.bitLength();
		_authority._secretShare = new BigInteger(bitlen, new SecureRandom());
		_authority._publicShare = _authority._ecParam.getG().multiply(_authority._secretShare);
		_authority._sumPubShare = _authority._ecParam.getG().multiply(_authority._secretShare);
		
		///Build the GenPubKey mesage
		Document newdoc = new Document(new Element(Authority.GENPUBKEY));
		Element root = newdoc.getRootElement();
		
		String selfid = _authority._selfVoter.get_id(); 
		Element eId = new Element(Authority.GENPUBKEY_ID).setText(selfid);				
		root.addContent(eId);
		
		_authority._shareTable.put(selfid, _authority._publicShare); //store the share
		byte[] bytesPt = new X9ECPoint(_authority._publicShare).getDEREncoded();
		Element eFactor = new Element(Authority.GENPUBKEY_FACTOR).setText(
				Base64.encodeBase64String(bytesPt));
		root.addContent(eFactor);
		
		String serialXML = Utility.XMLElemToString(eId, eFactor);
//		_log.debug("---serialXML="+serialXML);
		String sig64 = Utility.genSignature(_authority._priKey, serialXML);
		root.addContent(new Element(Authority.GENPUBKEY_SIG).setText(sig64));
//		if(! Utility.VerifyBase64Sig(serialXML, sig64, _authority._pubKey))
//			throw new SignatureException("WTF?? signature not right!!");
		
		///public the public share to *other* bulletins
		for(AuthorityInfo info : _authority._authoritiesInfo){
			InetSocketAddress addr = info.get_addr();
			String targetId = info.get_authId();
			String selfId = _authority._selfVoter.get_id();
			if(targetId.equals(selfId)) //don't send GenPubKey msg to self
				continue;
			Utility.sendXMLDocToPeer(newdoc, selfId, 
					addr, targetId, _authority._sslCtx); //send the xmldoc to remote peer
		}
		
		
	}
	
	
	
	/**
	 * receive notification from Manager,
	 * process local tally,
	 * publish `PubFactor' msg to *other* authorities	
	 * @throws TallyException 
	 * @throws NoSuchAlgorithmException 
	 */
	public void procVoteEnd(Document doc, SSLSocket soc) throws TallyException, NoSuchAlgorithmException{
		if( _authority._tally == null){
			_log.error("No tally is available");
			throw new TallyException("No tally available");
		}		
		
		///create witness and proof
		ASN1EncodableVector vecWitness = new ASN1EncodableVector();
		ASN1EncodableVector vecProof = new ASN1EncodableVector();
		Vector<CipherText> tally = _authority._tally;
		BigInteger Sj = _authority._secretShare;		
		for(int i=0; i<tally.size(); ++i){
			ECPoint X = tally.get(i).getX();
			ECPoint Wj = X.multiply(Sj);
			synchronized(_cipherPrivateKey){
				_cipherPrivateKey.set(i, _cipherPrivateKey.get(i).add(Wj));
			}
			vecWitness.add(new X9ECPoint(Wj));			
			SecShareProof ssp = SecShareProof.createProof(
					_authority._ecParam, X, Sj); 
			vecProof.add(ssp.serialToSeq());
		}
		
		///create document
		Document newdoc = new Document(new Element(Authority.PUBFACTOR));
		Element root = newdoc.getRootElement();
		Element eWit = new Element(Authority.PUBFACTOR_WITNESS);
		Element eProof = new Element(Authority.PUBFACTOR_PROOF);
		eWit.setText(
				Base64.encodeBase64String(new DERSequence(vecWitness).getDEREncoded()));
		eProof.setText(
				Base64.encodeBase64String(new DERSequence(vecProof).getDEREncoded()));
		root.addContent(eWit);
		root.addContent(eProof);
		
		///send the document to all *other* authorities
		String selfId = _authority._selfVoter.get_id();
		for(AuthorityInfo ainfo : _authority._authoritiesInfo){
			if(selfId.equals(ainfo.get_authId())) //pass self
				continue;
			Utility.sendXMLDocToPeer(newdoc, selfId, 
					ainfo.get_addr(), ainfo.get_authId(), _authority._sslCtx);
		}
	}
}
