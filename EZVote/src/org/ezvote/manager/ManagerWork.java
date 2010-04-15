package org.ezvote.manager;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLSocket;

import org.apache.log4j.Logger;
import org.ezvote.authority.Authority;
import org.ezvote.authority.AuthorityInfo;
import org.ezvote.util.Utility;
import org.ezvote.util.WorkSet;
import org.ezvote.voter.Voter;
import org.ezvote.voter.VoterInfo;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;

public class ManagerWork implements WorkSet {
	
	/**
	 * this is a group of interaction
	 * 1. voter->manager: VoteReg
	 * 2. manager->voter: challenge
	 * 3. voter->manager: response
	 * 4. manager->voter: whether voter is eligible
	 * @throws CertificateException 
	 * @throws IOException 
	 * @throws UnsupportedEncodingException 
	 * @throws JDOMException 
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	private enum state_{OK, SIG_ERR, ID_NON_ELIGIBLE, TIMEOUT}
	
	private static Logger _log = Logger.getLogger(ManagerWork.class); 
	
	private Manager _manager;

	private static String[] _desc = new String[]{
		"VoteReg", "procVoteReg", //note: this is a group of interaction
		"GenPubKeyFinish", "procGenPubKeyFinish"		
	};

	/**
	 * process `GenPubKeyFinish' msg, after all authorities sent their msg,
	 * send `DistVoteStart' msg back 
	 */
	AtomicInteger _gotPKFmsg = new AtomicInteger();
	
	public ManagerWork(Manager manager) {
		_manager = manager;
	};
	@Override
	public String[] getWorkDesc() {
		return _desc;
	}
	
	public void procGenPubKeyFinish(Document doc, SSLSocket soc) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException{
		String encPubKey = doc.getRootElement().getChildText(Authority.GENPUBKEYFINISH_PUBKEY);
		_log.info("receive encryption public key: "+encPubKey);
		
		if(_gotPKFmsg.addAndGet(1) == _manager._authorities.size()){//all authorities sent
			Document newdoc = new Document(new Element(Manager.DISTVOTESTART));
			Element eRoot = newdoc.getRootElement();
			
			Element eVoteStart = new Element(Manager.DISTVOTESTART_VOTESTART);
			
			Element eCurveName = new Element(Authority.VOTESTART_CURVENAME);
			eCurveName.setText(_manager._voteContent.get_CurveName());
			eVoteStart.addContent(eCurveName);
			
			Element ePubKey = new Element(Authority.VOTESTART_PUBKEY);
			ePubKey.setText(encPubKey);
			eVoteStart.addContent(ePubKey);
						
			Element eDeadline = new Element(Authority.VOTESTART_DEADLINE);
			eDeadline.setText(String.valueOf(_manager._voteContent.get_deadline().getTime()));
			eVoteStart.addContent(eDeadline);
			
			Element eBuls = new Element(Authority.VOTESTART_BULLETINS);
			for(AuthorityInfo ainfo : _manager._authorities){
				Element eAddr = new Element(Authority.VOTESTART_BULLETINS_ADDR);
				eAddr.setAttribute(Authority.VOTESTART_BULLETINS_ADDR_ID, ainfo.get_authId());
				eAddr.setText(ainfo.get_addr().toString());
				eBuls.addContent(eAddr);
			}
			
			eVoteStart.addContent(eBuls);
			
			String serialXML = Utility.XMLElemToString(eCurveName, ePubKey, eDeadline, eBuls);
			String sig64 = Utility.genSignature(_manager._priKey, serialXML);
			Element eSig = new Element(Authority.VOTESTART_SIG);
			eSig.setText(sig64);
			
			eVoteStart.addContent(eSig);
			
			eRoot.addContent(eVoteStart);
			///create document done
			
			///send document to authorities
			for(AuthorityInfo ainfo : _manager._authorities){
				Utility.sendXMLDocToPeer(newdoc, _manager._self.get_id(),
						ainfo.get_addr(), ainfo.get_authId(), _manager._sslCtx);
			}
		}
	}
	public void procVoteReg(Document doc, SSLSocket soc) throws CertificateException, UnsupportedEncodingException, IOException, JDOMException, InvalidKeyException, NoSuchAlgorithmException, SignatureException{
		state_ ret = state_.OK;
//		Utility.logInConnection(soc, _manager._self.get_id());
		
		PublicKey voterPubkey = Utility.getPeerPubKey(soc);
		BufferedReader in = new BufferedReader(
				new InputStreamReader(soc.getInputStream(), Utility.ENCODING));
		BufferedWriter out = new BufferedWriter(
				new OutputStreamWriter(soc.getOutputStream(), Utility.ENCODING));
		
		///send `Challenge' msg
		_log.debug("send Challenge to voter");
		Document docChallenge = new Document(new Element(Manager.CHALLENGE));
		docChallenge.getRootElement().setText(_manager._voteContent.get_sessionId());
		Utility.XMLDocToWriter(docChallenge, out);
		
		///read and process `Response' msg
		_log.debug("read and process Response from voter");
		Document docResp = Utility.ReaderToXMLDoc(in);
		Element rootResp = docResp.getRootElement();
		String vid = rootResp.getChildText(Voter.RESPONSE_ID);
		String addrstr = rootResp.getChildText(Voter.RESPONSE_LISTEN);
		String sig64 = rootResp.getChildText(Voter.RESPONSE_SIG);
		if( ! Utility.VerifyBase64Sig(_manager._voteContent.get_sessionId(),
				sig64, voterPubkey) ){ //signature invalid
			ret = state_.SIG_ERR;
		}else if(! _manager._eliRule.isEligible(vid)){ //id not eligible
			ret = state_.ID_NON_ELIGIBLE;
		}else{ //ok, send back normal
			ret = state_.OK;
		}
		
		///send back
		if( ret == state_.OK){
			InetSocketAddress voterAddr = Utility.parseInetSocketAddress(addrstr);
			VoterInfo vinfo = new VoterInfo(voterAddr, vid);
			_manager._voters.add(vinfo);
			Document docContent = _manager._voteContent.getDocument();
			Utility.XMLDocToWriter(docContent, out);
		}else{
			String reason = null;
			switch(ret){
			case SIG_ERR:
				reason = "signature invalid";
				break;
			case ID_NON_ELIGIBLE:
				reason = "ID not eligible";
				break;
			case TIMEOUT:
				reason = "the registration phase is over";
				break;				
			}
			Document docFail = new Document(new Element(Manager.REGFAILURE));
			docFail.getRootElement().addContent(new Element(Manager.REGFAILURE_REASON).setText(reason));
			Utility.XMLDocToWriter(docFail, out);
		}
	}

}
