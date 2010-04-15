package org.ezvote.voter;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;

import javax.net.ssl.SSLSocket;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.ezvote.SignatureException;
import org.ezvote.authority.Authority;
import org.ezvote.authority.AuthorityInfo;
import org.ezvote.authority.AuthorityWork;
import org.ezvote.crypto.CipherTextWithProof;
import org.ezvote.crypto.ProofException;
import org.ezvote.crypto.VoteCipher;
import org.ezvote.manager.Manager;
import org.ezvote.util.DispatcherException;
import org.ezvote.util.Utility;
import org.ezvote.util.WorkSet;
import org.jdom.Document;
import org.jdom.Element;

public class VoterWork implements WorkSet {
	
	private static Logger _log = Logger.getLogger(VoterWork.class);
	
	///private variables
	private Voter _voter;
	private Authority _authority = null; //only available after receive Upgrade message from Manager
	private String[] _desc = new String[]{
			"Upgrade" , "procUpgrade",
			"VoteStart", "procVoteStart",
			"Result", "procResult"
	};	
	
	///init
	VoterWork(Voter voter){_voter = voter;}
	
	@Override
	public String[] getWorkDesc(){return _desc;}
	
	/**
	 *  display the result 
	 */
	public void procResult(Document doc, SSLSocket soc){
		List<Element> lstOption = doc.getRootElement().getChildren(Authority.RESULT_OPTION);
		String[] res = new String[lstOption.size()];
		int i=0;
		for(Element e : lstOption){
			res[i++] = new String(e.getTextTrim() + " : " +
					e.getAttributeValue(Authority.RESULT_OPTION_COUNT));
		}
		_voter._ui.displayVoteResult(res);
	}
	
	///proc-* functions
	/**
	 * process <code>Upgrade</code> xml message, create Authority&AuthorityWork instance,
	 * add AuthorityWork to Dispatcher
	 * @throws IOException 
	 */
	@SuppressWarnings("unchecked")
	public void procUpgrade(Document doc, SSLSocket soc) throws SignatureException, DispatcherException, IOException{
		_log.info("procUpgrade");
		Element root = doc.getRootElement();
		Element elemBuls = root.getChild(Manager.UPGRADE_BULLETINS);
		Element elemVoters = root.getChild(Manager.UPGRADE_VOTERS);
		Element elemCurveName = root.getChild(Manager.UPGRADE_CURVENAME);
		String serialXML = Utility.XMLElemToString(elemBuls, elemVoters, elemCurveName); //serial the bulletins & voters elements into xml string
		String sig64 = root.getChildTextTrim(Manager.UPGRADE_SIG);
		
		try{
			if( ! Utility.VerifyBase64Sig(serialXML, sig64, _voter._mgrPubKey))
				throw new SignatureException("'Upgrade' message signature verification failure");			
		}catch(Exception e){
			throw new SignatureException("'Upgrade' message signature verification failure");
		}
		
		///create Authority & AuthorityWork, add authority-related work to Dispatcher at last
		String curveName = elemCurveName.getTextTrim();
		VoterInfo self = new VoterInfo(_voter._localListen, _voter._userId);
		_authority = new Authority(_voter._sslCtx,
				_voter._priKey,
				_voter._pubKey,
				self, 
				_voter._mgrInfo,
				curveName);		
		
		///parse the Bulletins element, extract all authorities info
		List<Element> lstBul = elemBuls.getChildren(Manager.UPGRADE_BULLETINS_ADDR);
		AuthorityWork awork = new AuthorityWork(_authority, _voter, lstBul.size());
		for(Element bul : lstBul){
			String bid = bul.getAttributeValue(Manager.UPGRADE_BULLETINS_ADDR_ID);
			String addr = bul.getTextTrim(); //ip/host:port
			InetSocketAddress socAddrOfBulletin = 
				Utility.parseInetSocketAddress(addr);
			
			AuthorityInfo ainfo = new AuthorityInfo(socAddrOfBulletin, bid);
			_authority.get_authoritiesInfo().add(ainfo); //add the authority info into authority instance
		}
		
		///parse the Voters element, extract all voters info
		List<Element> lstVtr = elemVoters.getChildren(Manager.UPGRADE_VOTERS_ADDR);
		for(Element vtr : lstVtr){
			String vid = vtr.getAttributeValue(Manager.UPGRADE_VOTERS_ADDR_ID);
			String addr = vtr.getTextTrim();
			InetSocketAddress socAddrOfVoter = 
				Utility.parseInetSocketAddress(addr);
			
			VoterInfo vinfo = new VoterInfo(socAddrOfVoter, vid);
			_authority.get_votersInfo().add(vinfo);			
		}
		
		_voter._disp.addWorkSet(awork);//add new work to dispatcher
		
		///send ACK to manager
		BufferedWriter socbw = new BufferedWriter(new OutputStreamWriter(soc.getOutputStream(), Utility.ENCODING));
		Document ackdoc = new Document(new Element(Utility.ACK));
		Utility.XMLDocToWriter(ackdoc, socbw);
	}
	
	/**
	 * process <code>VoteStart</code> xml message, 	
	 * display deadline and get ballot, send it to bulletins
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws ProofException 
	 * @throws IOException 
	 * @throws UnsupportedEncodingException 
	 * @throws java.security.SignatureException 
	 * @throws InvalidKeyException 
	 */
	public void procVoteStart(Document doc, SSLSocket soc) throws SignatureException, NoSuchAlgorithmException, InvalidKeySpecException, ProofException, UnsupportedEncodingException, IOException, InvalidKeyException, java.security.SignatureException{
		_log.info("procVoteStart");
		Element root = doc.getRootElement();
		Element eCurveName = root.getChild(Authority.VOTESTART_CURVENAME);
		Element ePubKey = root.getChild(Authority.VOTESTART_PUBKEY);
		Element eDeadline = root.getChild(Authority.VOTESTART_DEADLINE);
		Element eBulletins = root.getChild(Authority.VOTESTART_BULLETINS);
		String serialXML = Utility.XMLElemToString(eCurveName, ePubKey, eDeadline, eBulletins);
		String sig64 = root.getChildTextTrim(Authority.VOTESTART_SIG);
		
		try{
			if( ! Utility.VerifyBase64Sig(serialXML, sig64, _voter._mgrPubKey))
				throw new SignatureException("'VoteStart' message signature verification failure");			
		}catch(Exception e){
			throw new SignatureException("'VoteStart' message signature verification failure");
		}
		
		String curveName = eCurveName.getTextTrim();
		ECParameterSpec ecParam = ECNamedCurveTable.getParameterSpec(curveName);
		byte[] bytesPubKey = Base64.decodeBase64(ePubKey.getTextTrim());
		_voter._castPubkey = new X9ECPoint(ecParam.getCurve(),
				(ASN1OctetString)new ASN1InputStream(bytesPubKey).readObject()).getPoint();
		
		long time = Long.parseLong(eDeadline.getTextTrim());
		_voter._deadline = new Date();
		_voter._deadline.setTime(time);
		
		List<Element> lstBul = eBulletins.getChildren(Authority.VOTESTART_BULLETINS_ADDR);
		for(Element bul : lstBul){
			String bid = bul.getAttributeValue(Authority.VOTESTART_BULLETINS_ADDR_ID);
			String addr = bul.getTextTrim();
			InetSocketAddress socAddrOfBulletin = 
				Utility.parseInetSocketAddress(addr);
			
			AuthorityInfo ainfo = new AuthorityInfo(socAddrOfBulletin, bid);
			_voter._authoritiesInfo.add(ainfo);
		}
		
		
		/////CAST BALLOT START//////////
		
		///get ballot, encrypt it, make proof
		boolean[] votelst = _voter._ui.getBallot();
		
		ASN1EncodableVector voteVec = new ASN1EncodableVector();
		ASN1EncodableVector proofVec = new ASN1EncodableVector();
		VoteCipher cipher = new VoteCipher(ecParam, _voter._castPubkey);
		
		try {
			for(boolean b : votelst){
				ECPoint clearText = null;
				if(b){ //if true
					clearText = ecParam.getG();
				}else{
					clearText = ecParam.getG().negate();
				}

				CipherTextWithProof ctwp = cipher.encryptAndProve(clearText);
				voteVec.add(ctwp.get_ct().serialToSeq());
				proofVec.add(ctwp.get_vp().serialToSeq());
//				_log.debug("---VOTE PROOF TEST VERIFY---");
//				if( ! ctwp.get_vp().verifyProof(
//						ctwp.get_ct(), ecParam, _voter._castPubkey) ){
//					_log.error("---VOTE PROOF TEST FAILED---");
//				}else{
//					_log.debug("---VOTE PROOF TEST SUCCEEDED---");
//				}
			}
		} catch (ProofException e) {
			_log.error("error in make proof", e);
			throw e;
		}
		
		Document newdoc = new Document(new Element(Voter.BALLOT));
		Element eVote = new Element(Voter.BALLOT_VOTE);
		eVote.setText(Base64.encodeBase64String(
				new DERSequence(voteVec).getDEREncoded()));
		Element eProof = new Element(Voter.BALLOT_PROOF);
		eProof.setText(Base64.encodeBase64String(
				new DERSequence(proofVec).getDEREncoded()));
		Element eSig = new Element(Voter.BALLOT_SIG);
		String serialXML2 = Utility.XMLElemToString(eVote, eProof);
		eSig.setText(Utility.genSignature(_voter._priKey, serialXML2));
				
		newdoc.getRootElement().addContent(eVote);
		newdoc.getRootElement().addContent(eProof);
		newdoc.getRootElement().addContent(eSig);
		
		///send the msg to bulletins
		for(AuthorityInfo ainfo : _voter._authoritiesInfo){
			Utility.sendXMLDocToPeer(newdoc, _voter._userId,
					ainfo.get_addr(), ainfo.get_authId(), _voter._sslCtx);			
		}

	}
}
