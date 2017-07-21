<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.io.*,java.util.*,http_pfx_client.jsslclient"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>response_signcert_pfx</title>
</head>
<body>
<h1></h1>
<ul>
<li><p><b>response signcert_pfx:</b>
<br/>
<%
String IP = request.getParameter("IP");
String Port = request.getParameter("Port");
String Cookie = request.getParameter("Cookie");
String Signcert = request.getParameter("Signcert");
String Password = request.getParameter("Password");
String[] signcert_pfx = _client.request_sign_pfx(true, IP, Integer.parseInt(Port), Cookie, Signcert, Password);
%>
SIGNCERT_PFX:
<%=signcert_pfx[0]%>
</p></li>
</ul>
</body>
</html>
