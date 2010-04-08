package org.ezvote.voter;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.List;

import javax.net.ssl.SSLSocket;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.ezvote.SignatureException;
import org.ezvote.authority.Authority;
import org.ezvote.authority.AuthorityInfo;
import org.ezvote.authority.AuthorityWork;
import org.ezvote.manager.Manager;
import org.ezvote.util.DispatcherException;
import org.ezvote.util.Utility;
import org.ezvote.util.WorkSet;
import org.jdom.Document;
import org.jdom.Element;

class VoterWork implements WorkSet {
	
	private static Logger _log = Logger.getLogger(VoterWork.class);
	
	///private variables
	private Voter _voter;
	private Authority _authority = null; //only available after receive Upgrade message from Manager
	private String[] _desc = new String[]{
			"Upgrade" , "procUpgrade",
			"VoteStart", "procVoteStart"
	};	
	
	///init
	VoterWork(Voter voter){_voter = voter;}
	
	@Override
	public String[] getWorkDesc(){return _desc;}
	
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
		_authority = new Authority(_voter._sslCtx, _voter._priKey, self, _voter._mgrInfo, curveName);
		AuthorityWork awork = new AuthorityWork(_authority);
		
		///parse the Bulletins element, extract all authorities info
		List<Element> lstBul = elemBuls.getChildren(Manager.UPGRADE_BULLETINS_ADDR); 
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
	}
	
	/**
	 * process <code>VoteStart</code> xml message, 	
	 * display deadline and get ballot, send it to bulletins
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public void procVoteStart(Document doc, SSLSocket soc) throws SignatureException, NoSuchAlgorithmException, InvalidKeySpecException{
		_log.info("procVoteStart");
		Element root = doc.getRootElement();
		Element ePubKey = root.getChild(Authority.VOTESTART_PUBKEY);
		Element eDeadline = root.getChild(Authority.VOTESTART_DEADLINE);
		Element eBulletins = root.getChild(Authority.VOTESTART_BULLETINS);
		String serialXML = Utility.XMLElemToString(ePubKey, eDeadline, eBulletins);
		String sig64 = root.getChildTextTrim(Authority.VOTESTART_SIG);
		
		try{
			if( ! Utility.VerifyBase64Sig(serialXML, sig64, _voter._mgrPubKey))
				throw new SignatureException("'VoteStart' message signature verification failure");			
		}catch(Exception e){
			throw new SignatureException("'VoteStart' message signature verification failure");
		}
		
		byte[] bytesPubKey = Base64.decodeBase64(ePubKey.getTextTrim()); 
		X509EncodedKeySpec spec = new X509EncodedKeySpec(bytesPubKey);
		KeyFactory factory = KeyFactory.getInstance(Utility.KEYSPEC_ALG);
		_voter._castPubkey = factory.generatePublic(spec); ///store the PubKey used to encrypt ballot
		
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
		
		///get ballot, encrypt it, make a proof, send to bulletins
		List<Boolean> votelst = _voter._ui.getBallot();
		for(Boolean b : votelst){
			
		}
		
	}
	
}
