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
  </head>

  <body>
    <h1>Thank you for trying CPK keygen</h1><br>
    <%
       String strTimeZone = application.getInitParameter("TimeZone");
       Calendar c = Calendar.getInstance(TimeZone.getTimeZone(strTimeZone));
       String time = String.format("%1$tc", c);
    %>
    <h2>current time: <%=time%> </h2><br>  
	
    <table>
      <tr>
        <td colspan="2" style="font-weight:bold;">Please authenticate with openid first:</td>        
      </tr>
      <tr>
        <td><a href="/keygen/GenKey">Authenticate me!</a></td>
      </tr>
    </table>
  </body>
</html>
