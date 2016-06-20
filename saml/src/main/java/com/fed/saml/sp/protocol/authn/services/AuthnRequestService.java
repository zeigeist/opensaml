package com.fed.saml.sp.protocol.authn.services;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.authn.handlers.SAMLAuthnRequest;

public class AuthnRequestService extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(AuthnRequestService.class);

    @Override
    protected void doGet(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException, IOException {
    	logger.info("In doGet() of AuthnRequestService");
    	logger.info("Have to do user authentication");
    	logger.info("Create and send SAML AuthnRequest to IdP");
    	
    	processRequest(httpRequest, httpResponse);
    }
    
    protected void processRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse) 
			throws ServletException, IOException {

    	if("get".equalsIgnoreCase(httpRequest.getMethod())) {
        	SAMLAuthnRequest samlAuthnRequest = new SAMLAuthnRequest();
        	samlAuthnRequest.sendAuthRequest(httpResponse);
		}
	}
}