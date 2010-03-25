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
	
	public JdoSecMatrix(byte[] bSecmatrix, Date dStart, Date dEnd){
		bytesSecmatrix = new Blob(bSecmatrix);
		start = dStart;
		end = dEnd;
	}

	///getters and setters
	public Blob get_bytesSecmatrix() {
		return bytesSecmatrix;
	}	

	public Date get_start() {
		return start;
	}

	public Date get_end() {
		return end;
	}
	
	public void set_bytesSecmatrix(Blob mBytesSecmatrix) {
		bytesSecmatrix = mBytesSecmatrix;
	}

	public void set_start(Date mStart) {
		start = mStart;
	}

	public void set_end(Date mEnd) {
		end = mEnd;
	}
	
}
