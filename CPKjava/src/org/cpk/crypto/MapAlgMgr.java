package org.cpk.crypto;

import java.util.Properties;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import org.apache.log4j.Logger;

/**
 * MapAlgMgr provides some functions for client to get {@link org.cpk.crypto.MapAlg MapAlg} instance from name/oid 
 * @author zaexage@gmail.com
 */
public class MapAlgMgr {
	static private Logger logger = Logger.getLogger(MapAlgMgr.class);
	static Properties s_name_class_mapping = new Properties(); /// <algname, algClassName> pairs
	static Properties s_id_name_mapping = new Properties(); /// <algOID, algname> pairs
	
	/**
	 * initialize the MapAlgMgr with two resource files.
	 * @param name_class the file which contains the <algorithm_name, algorithm_classname> pairs
	 * @param id_name the file which contains the <algorihtm_oid, algorithm_name> pairs
	 * @throws IOException
	 * @see MapAlg
	 * @see <a href="http://en.wikipedia.org/wiki/Object_identifier">OID</a>
	 */
	static public void Configure(String name_class, String id_name) throws IOException{
		//try to load from classpath
		InputStream name_class_is = MapAlgMgr.class.getResourceAsStream("/"+name_class);
		InputStream id_name_is = MapAlgMgr.class.getResourceAsStream("/"+id_name);
						
		s_name_class_mapping.load(new BufferedReader(new InputStreamReader(name_class_is, "UTF-8")));
		s_id_name_mapping.load(new BufferedReader(new InputStreamReader(id_name_is, "UTF-8")));
	}
	
	/**
	 * get a {@link org.cpk.crypto.MapAlg MapAlg} instance from given algorithm name
	 * @param algNameWithParam the name of mapping algorithm, it could contains a parameter after `_', e.g.: DigestMap_SHA512
	 * @return the MapAlg instance
	 * @throws SecurityException
	 * @throws NoSuchMethodException
	 * @throws IllegalArgumentException
	 * @throws InstantiationException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 * @throws ClassNotFoundException
	 */
	static public MapAlg GetMapAlg(String algNameWithParam)	throws SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException, ClassNotFoundException{
		String[] splitted = algNameWithParam.split("_", 2);
		String algName = splitted[0];		
		String classname = s_name_class_mapping.getProperty(algName);
		if(null == classname)
			throw new IllegalArgumentException("the class name not found in properties file:" + algName );
		else{			
			Class c = Class.forName(classname);
			if(splitted.length > 1){ //if has parameter
				Constructor<MapAlg> con = c.getConstructor(String.class);
				return (MapAlg)con.newInstance(splitted[1]);
			}else{
				return (MapAlg)c.newInstance();
			}			 			
		}		
	}
	
	/**
	 * get a {@link org.cpk.crypto.MapAlg MapAlg} instance from given algorithm OID
	 * @param oid the object identifier of the mapping algorithm
	 * @return the MapAlg instance
	 * @throws SecurityException
	 * @throws IllegalArgumentException
	 * @throws NoSuchMethodException
	 * @throws InstantiationException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 * @throws ClassNotFoundException
	 */
	static public MapAlg GetMapAlgByOID(String oid) throws SecurityException, IllegalArgumentException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, ClassNotFoundException{
		String algNameWithParam = s_id_name_mapping.getProperty(oid);
		return GetMapAlg(algNameWithParam);
	}
}
