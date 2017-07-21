<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.io.*,java.util.*,http_pfx_client.jsslclient"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>response_p10</title>
</head>
<body>
<h1></h1>
<ul>
<li><p><b>response p10:</b>
<br/>
<%
String IP = request.getParameter("IP");
String Port = request.getParameter("Port");
String KeyBits = request.getParameter("KeyBits");
String DigestAlg = request.getParameter("DigestAlg");
jsslclient _client = new jsslclient();
String[] s_arr = _client.request_p10(true, IP, Integer.parseInt(Port), Integer.parseInt(KeyBits), DigestAlg);
%>
IP:=
<%=IP%>
<br/>
Port:=
<%=Port%>
<br/>
KeyBits:=
<%=KeyBits%>
<br/>
DigestAlg:=
<%=DigestAlg%>
<br/>
Cookie:=
<%=s_arr[0]%>
<br/>
P10:=
<%=s_arr[1]%>
<br/>
EncPubkey:=
<%=s_arr[2]%>
</p></li>
</ul>
</body>
</html>
