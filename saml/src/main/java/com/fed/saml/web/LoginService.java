package com.fed.saml.web;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoginService extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(LoginService.class);
	private RequestDispatcher loginJSPRequestDispatcher;

	static {
		
	}
	
	public void init(ServletConfig config) throws ServletException {
		logger.info("In init() of LoginService");
		ServletContext context = config.getServletContext();
		loginJSPRequestDispatcher = context.getRequestDispatcher("/WEB-INF/jsp/login.jsp");
	}

	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		logger.info("In doGet() of LoginService");
		logger.info("Forward request to login.jsp to do login");
		loginJSPRequestDispatcher.forward(req, resp);
	}

	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		logger.info("In doPost() of LoginService");
		int userid = 123;
		String user = "admin";
		String psswd = "admin";

		String username = req.getParameter("username");
		String password = req.getParameter("password");
		logger.info("Username : Password-> " + username + " : " + password);
		if (username != null && !username.isEmpty() && username.equals(user) && 
			password != null && !password.isEmpty() && password.equals(psswd)) {
			logger.info("Username and password are correct");
		} else {
			req.setAttribute("message", "Authentication failed.");
			logger.info("Username and password are incorrect");
			logger.info("Forward once again to login.jsp");
			loginJSPRequestDispatcher.forward(req, resp);
			return;
		}

		RequestDispatcher rd = req.getRequestDispatcher("/idp/sso"); // forward back to IdPSSOService
		logger.info("Login completed, so forward back to IdPSSOService");
		//req.setAttribute("userid", userid);
        rd.forward(req, resp);
	}
}
