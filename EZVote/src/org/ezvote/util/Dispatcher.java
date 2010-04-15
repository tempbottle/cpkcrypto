package org.ezvote.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Hashtable;

import javax.net.ssl.SSLSocket;

import org.apache.log4j.Logger;
import org.jdom.Document;

public class Dispatcher {
	
	private class Container{
		public WorkSet _wset;
		public Method _mtd;
		public Container(WorkSet wset, Method mtd){
			_wset = wset; _mtd = mtd;
		} 
	}
	
	private static Logger _log = Logger.getLogger(Dispatcher.class);
	
	private Hashtable<String, Container> _table = new Hashtable<String, Container>();
	
	public Dispatcher(){}
	
	/**
	 * add a WorkSet instance, add all <tag_string, method_name>
	 * pair into this Dispatcher
	 * @param wset WorkSet instance
	 * @throws DispatcherException 
	 */
	public void addWorkSet(WorkSet wset) throws DispatcherException{
		String[] desc = wset.getWorkDesc();
		assert(desc.length % 2 == 0);
		
		for(int i=0; i<desc.length; i+=2){
			String tag_string = desc[i];
			String method_name = desc[i+1];
			if( _table.containsKey(tag_string) ){ //if such tag_string already exists in hashtable, throw
				throw new DispatcherException("duplicate entry: " + tag_string);
			}
			
			Method mtd = null;
			try{
				mtd = wset.getClass().getMethod(method_name, 
						new Class<?>[]{Document.class, SSLSocket.class});
			}catch(NoSuchMethodException e){
				throw new DispatcherException("getMethod failure: " + method_name, e);
			}
			
			_table.put(tag_string, new Container(wset, mtd));
		}
	}
	
	public Object dispatch(String tag, Document doc, SSLSocket soc) throws DispatcherException{
		Container cont = _table.get(tag);
		if( null == cont ){
			_log.error("doc: " + doc.toString());
			throw new DispatcherException("unknown tag: " + tag);
		}
		try {
			Object obj = cont._mtd.invoke(cont._wset, doc, soc);
			return obj;
		} catch (IllegalArgumentException e) {
			throw new DispatcherException("dispatch failure", e);
		} catch (IllegalAccessException e) {
			throw new DispatcherException("dispatch failure", e);
		} catch (InvocationTargetException e) {
			throw new DispatcherException("dispatch failure", e);
		}
	}
	
}
