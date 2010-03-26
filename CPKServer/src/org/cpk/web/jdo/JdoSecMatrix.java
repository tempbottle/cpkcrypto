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
	
	public JdoSecMatrix(byte[] bSecmatrix, Date dStart, Date dEnd){
		bytesSecmatrix = new Blob(bSecmatrix);
		start = dStart;
		end = dEnd;
		certSerial = Integer.valueOf(1);
	}

	///getters and setters
	public Blob getBytesSecmatrix() {
		return bytesSecmatrix;
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
