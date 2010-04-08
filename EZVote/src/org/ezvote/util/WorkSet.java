package org.ezvote.util;

public interface WorkSet {
	
	/**
	 * get a group of work description in such order:
	 *  {
	 *  	"tag1", "method1",
	 *      "tag2", "method2"
	 *      ...
	 *  }
	 * @return an array of work description
	 */
	public String[] getWorkDesc();
	
}
