/**
 * this class is an adapter to utilize app engine JDO storage
 */
package org.cpk.web.jdo;

import java.util.Date;

import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;

import com.google.appengine.api.datastore.Blob;
import com.google.appengine.api.datastore.Key;

@PersistenceCapable
public class JdoSecMatrix {
	@PrimaryKey
	@Persistent(valueStrategy = IdGeneratorStrategy.IDENTITY)
    private Key key;
	
	@Persistent private Blob bytesSecmatrix;		
	@Persistent private Date start; //start time of secmatrix	 
	@Persistent private Date end; //end time of secmatrix
	@Persistent private Integer certSerial; //the cert serial, start at 1
	@Persistent private Blob bytesPubmatrix;
	
	public JdoSecMatrix(byte[] bSecmatrix, Date dStart, Date dEnd,
			byte[] bPubmatrix
		){
		bytesSecmatrix = new Blob(bSecmatrix);
		bytesPubmatrix = new Blob(bPubmatrix);
		start = dStart;
		end = dEnd;
		certSerial = Integer.valueOf(2); //1 is taken by server
	}

	///getters and setters
	public Blob getBytesSecmatrix() {
		return bytesSecmatrix;
	}

	public Blob getBytesPubmatrix() {
		return bytesPubmatrix;
	}	

	public Date getStart() {
		return start;
	}

	public Date getEnd() {
		return end;
	}

	public Integer getCertSerial() {
		return certSerial;
	}

	public void setBytesSecmatrix(Blob bytesSecmatrix) {
		this.bytesSecmatrix = bytesSecmatrix;
	}

	public void setBytesPubmatrix(Blob bytesPubmatrix) {
		this.bytesPubmatrix = bytesPubmatrix;
	}

	public void setStart(Date start) {
		this.start = start;
	}

	public void setEnd(Date end) {
		this.end = end;
	}

	public void setCertSerial(Integer certSerial) {
		this.certSerial = certSerial;
	}	
}
