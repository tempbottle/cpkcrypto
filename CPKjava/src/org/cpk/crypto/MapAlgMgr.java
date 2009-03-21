package org.cpk.crypto;

import java.util.Map;
import java.util.Properties;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.lang.reflect.Constructor;

import org.apache.log4j.Logger;

public class MapAlgMgr {
	static private Logger logger = Logger.getLogger(MapAlgMgr.class);
	static Properties s_name_class_mapping = new Properties(); // <algname, algClassName> pairs
	static Properties s_id_name_mapping = new Properties();
		
	static public void Configure(String name_class, String id_name) throws IOException{		
		s_name_class_mapping.load(new BufferedReader(new InputStreamReader(new FileInputStream(name_class), "UTF-8")));
		s_id_name_mapping.load(new BufferedReader(new InputStreamReader(new FileInputStream(id_name), "UTF-8")));
	}
	
	static public MapAlg GetMapAlg(String algNameWithParam)	throws Exception{
		String[] splitted = algNameWithParam.split("_", 2);
		String algName = splitted[0];		
		String classname = s_name_class_mapping.getProperty(algName);
		if(null == classname)
			throw new IllegalArgumentException("the class name not found in properties file:" + algName );
		else{
			try{
				Class c = Class.forName(classname);
				if(splitted.length > 1){ //if has parameter
					Constructor<MapAlg> con = c.getConstructor(String.class);
					return (MapAlg)con.newInstance(splitted[1]);
				}else{
					return (MapAlg)c.newInstance();
				}
			}catch(ClassNotFoundException ex){
				logger.error(ex.toString());
				throw ex;				
			}			 			
		}		
	}
	
	static public MapAlg GetMapAlgByOID(String oid) throws Exception{
		String algNameWithParam = s_id_name_mapping.getProperty(oid);
		return GetMapAlg(algNameWithParam);
	}
}
