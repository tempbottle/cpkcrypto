package org.ezvote.manager;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Date;

import org.ezvote.util.Utility;
import org.jdom.Document;
import org.jdom.Element;

public class VoteContent {
	private String _sessionId; //this vote's session id
	private String _content; // the vote's content
	private String[] _options; //options
	private Date _deadline; //deadline of vote
	
	private String _sig = null; //generated signature
	private Document _doc = null;//generated document
	
	public VoteContent(){}
	
	public void init(String sessionId, String content, String[] options, PrivateKey mgrPriKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException{
		///generate document
		_doc = new Document(new Element(Manager.VOTECONTENT));
		Element root = _doc.getRootElement();
		Element eSessionId = new Element(Manager.VOTECONTENT_SESSIONID).setText(sessionId); 
		root.addContent(eSessionId);
		Element eContent = new Element(Manager.VOTECONTENT_CONTENT).setText(content); 
		root.addContent(eContent);
		Element eOptions = new Element(Manager.VOTECONTENT_OPTIONS);
		root.addContent(eOptions);
		for(int i=0; i<options.length; ++i){
			Element eOp = new Element(Manager.VOTECONTENT_OPTIONS_OPTION);
			eOp.setText(options[i]);
			eOptions.addContent(eOp);
		}
		
		///generate sig
		String toBeSign = Utility.XMLElemToString(eSessionId, eContent, eOptions);
		_sig = Utility.genSignature(mgrPriKey, toBeSign);
		root.addContent(new Element(Manager.VOTECONTENT_SIG).setText(_sig));		
	}
	
	public Document getDocument(){
		return _doc;
	}

	public String get_sessionId() {
		return _sessionId;
	}

	public String get_content() {
		return _content;
	}

	public String[] get_options() {
		return _options;
	}

	public void set_deadline(Date deadline) {
		_deadline = deadline;
	}

	public Date get_deadline() {
		return _deadline;
	}
	
}
