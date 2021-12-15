<%--
  Created by IntelliJ IDEA.
  User: kmoha
  Date: 15-12-2021
  Time: 11:54
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charseet=US-ASCII">
    <title>Login Sucess Page</title>
</head>
<body>
<h3>Hi <%=request.getAttribute("user")%>,Login.successful</h3>
<a href="login.html">Login Page</a>
</body>
</html>
