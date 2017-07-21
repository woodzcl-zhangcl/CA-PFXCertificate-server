<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.io.*,java.util.*,http_pfx_client.jsslclient"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>response_signcert_enccert_pfx</title>
</head>
<body>
<h1></h1>
<ul>
<li><p><b>response signcert_enccert_pfx:</b>
<br/>
<%
String IP = request.getParameter("IP");
String Port = request.getParameter("Port");
String Cookie = request.getParameter("Cookie");
String Signcert = request.getParameter("Signcert");
String Enccert = request.getParameter("Enccert");
String Encprikey = request.getParameter("Encprikey");
String Encsymmetry = request.getParameter("Encsymmetry");
String Password=request.getParameter("Password");
String[] signcert_enccert_pfx = _client.request_sign_enc_pfx(true, IP, Integer.parseInt(Port), Cookie, Signcert, Enccert, Encprikey, Encsymmetry, Password);
%>
SIGNCERT_PFX:
<%=signcert_enccert_pfx[0]%>
<br/>
ENCCERT_PFX:
<%=signcert_enccert_pfx[1]%>
</p></li>
</ul>
</body>
</html>
