<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- The HTML 4.01 Transitional DOCTYPE declaration-->
<!-- above set at the top of the file will set     -->
<!-- the browser's rendering engine into           -->
<!-- "Quirks Mode". Replacing this declaration     -->
<!-- with a "Standards Mode" doctype is supported, -->
<!-- but may lead to some differences in layout.   -->
<%@ page import="java.util.Calendar" %>
<%@ page import="java.util.TimeZone" %>
<%@ page contentType="text/html; charset=UTF-8" %> 

<html>
  <head>
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <title>Welcome to CPK keygen webapp</title>
    <script type="text/javascript">
			function getKeyStore(){
				pass = document.getElementById("pass").value;
				newpath = "/keygen/GetKeyStore_"+pass;				
				window.location.href = newpath;				
			}
	</script>
  </head>

  <body>
    <h2>Thank you for trying CPK keygen</h2><br>
    <h3>We're using EC curve: <%= application.getInitParameter("EcCurveName")%> </h3><br> 
    <%
       String strTimeZone = application.getInitParameter("TimeZone");
       Calendar c = Calendar.getInstance(TimeZone.getTimeZone(strTimeZone));
       String time = String.format("%1$tc", c);
    %>
    <h2>current time: <%=time%> </h2><br>  
	
    <table>
      <tr>
        <td colspan="2" style="font-weight:bold;">If you want to get private key or get a Certificate, you need to authenticate with openid first</td>        
      </tr>      
      <tr>
        <td><a href="/keygen/GenKey">Get A PrivateKey</a></td>
      </tr>
      <tr>
        <td><a href="/keygen/GenCert">Get A Certificate</a></td>
      </tr>
      <tr><td colspan="2" style="font-weight:bold;">you also can get the private key and Certificate in one time(in BouncyCastle BKS format), you need to authenticate with openid first</td></tr>       
      <tr>
      	<td> keystore password:<input type=text maxLength="40" id="pass" value="test"/><input type="button" onclick="getKeyStore()" value="Get as keystore(BKS format)"/></td>
      </tr>
    </table>
    
    <br>
    If you only want to get the public matrix, just <a href="/GetPubMatrix">download it</a>
    Also, you could <a href="/GetRootCert">download</a> the root certificate of CPK keygen server
    
  </body>
</html>
