package org.cpk.web.servlet;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.Security;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.TimeZone;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cpk.crypto.MapAlgMgr;
import org.cpk.crypto.pubmatrix.PubMatrix;
import org.cpk.crypto.secmatrix.DERSecmatrixSerializer;
import org.cpk.crypto.secmatrix.SecMatrix;
import org.cpk.web.jdo.JdoSecMatrix;
import org.cpk.web.jdo.PMF;

import com.dyuproject.openid.RelyingParty;
import com.dyuproject.openid.ext.AxSchemaExtension;
/**
 * start authentication with OpenID
 * @author Administrator
 */
public class PrikeyGen extends HttpServlet {
	private static final long serialVersionUID = 4906098085632188831L;
	private static Logger logger = Logger.getLogger(PrikeyGen.class);
	
	/// strings indicating uri
	private static final String GENKEY = "/keygen/GenKey";
	private static final String GENKEY_CERT = "/keygen/GenKeyAndCert";
	private static final String GENCERT = "/keygen/GenCert";
	
	/// string indicating init parameters of Servlet
	private static final String EC_CURVE_NAME = "EcCurveName";
	private static final String ROW_CNT = "RowCnt";
	private static final String COL_CNT = "ColCnt";
	private static final String MAP_ALG = "MappingAlg";
	
	///secmatrix & pubmatrix
	SecMatrix m_secMatrix = null;
	PubMatrix m_pubMatrix = null;
	
	static
	{		
		RelyingParty.getInstance()
		.addListener(new AxSchemaExtension()
		.addExchange("email")
//		.addExchange("country")
//		.addExchange("language")
		);
	}
	
	
	@Override	
	public void init(ServletConfig config) throws ServletException{
		
		logger.info("Initialization start");
		
		try{
			MapAlgMgr.Configure("MapAlg.properties", "OIDMapAlg.properties");
		}catch(Exception ex){
			logger.error("Not all the configuration files are ready...exit", ex);
			logger.error("Maybe 'MapAlg.properties' or 'OIDMapAlg.properties' not present?", ex);
			throw new ServletException("PrikeyGen Init failed", ex);		
		}	
		
		if( -1 == Security.addProvider(new BouncyCastleProvider())){ //add this provider
			logger.error("Failed to add BouncyCastleProvider");
			throw new ServletException("PrikeyGen init failed");			
		}
		
		PersistenceManager pm = PMF.get().getPersistenceManager();
		SecMatrix secMatrix = null;
		try{
			logger.info("ready to init secmatrix");
			//if can find in JDO store, then deserialize it;
			//or create a new instance of SecMatrix and serialize to store
			
			String strTimeZone = config.getServletContext().getInitParameter("TimeZone");
			logger.debug("timezone="+strTimeZone);
			Calendar c = Calendar.getInstance(TimeZone.getTimeZone(strTimeZone));
			int year = c.get(Calendar.YEAR);
			c.clear();
			c.set(year, 0, 1, 0, 0, 0);
			Date start = c.getTime();
			c.set(year+1, 0, 1, 0, 0, 0);
			Date end = c.getTime();

			logger.info("query store for stored secmatrix");
			//construct query
			Query query = pm.newQuery(JdoSecMatrix.class, "this.start == date");
			query.declareParameters("java.util.Date date");
			List<JdoSecMatrix> result = (List<JdoSecMatrix>)query.execute(start);

			if(result.isEmpty()){
				//not found, create new instance
				logger.info("not found, create new one");
				String ecCurveName = config.getInitParameter(EC_CURVE_NAME);
				int rowCnt = Integer.parseInt(config.getInitParameter(ROW_CNT));
				int colCnt = Integer.parseInt(config.getInitParameter(COL_CNT));
				String mapAlg = config.getInitParameter(MAP_ALG);

				logger.info("generating secmatrix...");
				String AppURI = config.getServletContext().getInitParameter("AppURI");			
				secMatrix = SecMatrix.GenerateNewMatrix(rowCnt, colCnt, ecCurveName, mapAlg, new URI(AppURI));
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				DERSecmatrixSerializer serial = new DERSecmatrixSerializer(null, baos);
				serial.ExportSecMatrix(secMatrix);
				
				logger.info("generating secmatrix...done");
				
				logger.info("serializing secmatrix...");
				JdoSecMatrix jdoSecMatrix = new JdoSecMatrix(baos.toByteArray(), start, end);
				pm.makePersistent(jdoSecMatrix);				
				logger.info("serialize secmatrix... done");
			}else{
				//found, deserialize the bytes
				logger.info("found in storage, deserialize it...");
				assert(result.size() == 1);
				
				JdoSecMatrix jdoSecMatrix = result.get(0);
				ByteArrayInputStream bais = new ByteArrayInputStream(jdoSecMatrix.get_bytesSecmatrix().getBytes());
				DERSecmatrixSerializer serial = new DERSecmatrixSerializer(bais, null);
				secMatrix = serial.GetSecMatrix();
				
				logger.info("deserialize secmatrix... done");
			}
			
			/// generate pubmatrix from secmatrix
			logger.info("generate pubmatrix, this may take some time...");
			m_secMatrix = secMatrix;			
			m_pubMatrix = secMatrix.DerivePubMatrix();
			logger.info("generate pubmatrix, done");
			
		}catch (Exception e) {
			logger.error("Init secmatrix and pubmatrix failed", e);
			throw new ServletException("Init secmatrix and pubmatrix failed", e);
		}finally{
			pm.close();
		}
		
		logger.info("Initialization end");
	}
		
	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
		String requestUri = req.getRequestURI();
		logger.info("requestURL: " + req.getRequestURL());
		if(requestUri.equals(GENKEY)){
		
		}else if(requestUri.equals(GENCERT)){
			
		}else if(requestUri.equals(GENKEY_CERT)){
			
		}else{
			resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
		}
	}
	
	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
		doGet(req, resp);
	}
}
