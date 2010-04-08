package org.ezvote.authority;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Vector;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;
import javax.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.ezvote.manager.Manager;
import org.ezvote.util.Utility;
import org.ezvote.util.WorkSet;
import org.ezvote.voter.VoterInfo;
import org.jdom.Document;
import org.jdom.Element;

public class AuthorityWork implements WorkSet {
	
	private static Logger _log = Logger.getLogger(AuthorityWork.class);
	
	private Authority _authority;
	private boolean[] _authState = null; //whether an auth sent GenPubKey 
	private int _gotMsgCnt = 0; //how many GenPubKey msg got
	private String[] _desc = new String[]{
			"StartGenPubKey" , "procStartGenPubKey",
			"GenPubKey", "procGenPubKey",
			"DistVoteStart", "procDistVoteStart"
	};
	
	public AuthorityWork(Authority auth){ _authority = auth; }	

	@Override
	public String[] getWorkDesc() {
		return _desc;
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
		
		Element eId = new Element(Authority.GENPUBKEY_ID).setText(
				_authority._selfVoter.get_id());
		root.addContent(eId);
		
		byte[] bytesPt = new X9ECPoint(_authority._publicShare).getDEREncoded();
		Element eFactor = new Element(Authority.GENPUBKEY_FACTOR).setText(
				Base64.encodeBase64String(bytesPt));
		root.addContent(eFactor);
		String serialXML = Utility.XMLElemToString(eId, eFactor);
		root.addContent(new Element(Authority.GENPUBKEY_SIG).setText(
				Utility.genSignature(_authority._priKey, serialXML)));
		
		///public the public share to other bulletins
		for(AuthorityInfo info : _authority._authoritiesInfo){
			InetSocketAddress addr = info.get_addr();
			String targetId = info.get_authId();			
			Utility.sendXMLDocToPeer(newdoc, _authority._selfVoter.get_id(), 
					addr, targetId, _authority._sslCtx); //send the xmldoc to remote peer
		}
		
		///init an datastructure to indicate whether an authority has send GenPubKey msg
		_authState = new boolean[_authority._authoritiesInfo.size()];
		for(int i=0; i<_authState.length; ++i)
			_authState[i] = false;
	}

	/**
	 *	add this piece of pass-in public-share to sum 
	 * @throws SSLPeerUnverifiedException 
	 * @throws SignatureException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public void procGenPubKey(Document doc, SSLSocket soc) throws SSLPeerUnverifiedException, SignatureException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException{
		_log.debug("procGenPubKey");
		Element root = doc.getRootElement();
		Element eId = root.getChild(Authority.GENPUBKEY_ID);
		Element eFactor = root.getChild(Authority.GENPUBKEY_FACTOR);
		String serialXML = Utility.XMLElemToString(eId, eFactor); 
		String sig64 = root.getChildTextTrim(Authority.GENPUBKEY_SIG);
		
		X509Certificate cert = soc.getSession().getPeerCertificateChain()[0];
		String peerId = Utility.getSubjectFromPrinciple((X500Principal)cert.getSubjectDN());
		String idInE = eId.getTextTrim();
		if( ! peerId.equals(idInE) )
			throw new CertificateException("id in msg differs from id in certificate");
		
		PublicKey peerPubKey = cert.getPublicKey(); //get the peer's pubkey
		
		try{
			if( ! Utility.VerifyBase64Sig(serialXML, sig64, peerPubKey))
				throw new SignatureException("'GenPubKey' message signature verification failure");			
		}catch(Exception e){
			throw new SignatureException("'GenPubKey' message signature verification failure");
		}		
		///verify signature done
		
		///check whether this peer is authority, and whether already send this msg		
		boolean isAuthAndNew = false; 
		for(int i=0; i<_authority._authoritiesInfo.size(); ++i){
			AuthorityInfo ainfo = _authority._authoritiesInfo.get(i);
			if(ainfo._authId.equals(idInE)){
				if(! _authState[i]){ //not sent yet
					_authState[i] = true;
					_gotMsgCnt ++;
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
							new DEROctetString(bytesPubShare)).getPoint();
		_authority._sumPubShare = _authority._sumPubShare.add(pt); //sum the pass-in pub-share
		
		///if got all share, pub the generated pubkey(an ecpt) to manager, <GenPubKeyFinish>
		if(_gotMsgCnt == _authority._authoritiesInfo.size()){
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
	 * get from Manager the `VoteStart' msg, broadcast it to voters 
	 */
	public void procDistVoteStart(Document doc, SSLSocket soc){
		
		_log.info("procDistVoteStart");
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
		
		final Vector<VoterInfo> voters = _authority._votersInfo;
		for(int i=start; i<start+share; ++i){ //send to each voter
			VoterInfo v = voters.get(i);
			Document newdoc = new Document((Element) doc.getRootElement().
					getChild(Manager.DISTVOTESTART_VOTESTART).detach());
			Utility.sendXMLDocToPeer(newdoc, _authority._selfVoter.get_id(),
					v.get_addr(), v.get_id(), _authority._sslCtx);
		}
				
	}
	
}
