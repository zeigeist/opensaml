package com.fed.saml.sp.protocol.authn.services;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.authn.handlers.AuthnRequestHandler;

/**
 * The filter intercepts the user and start the SAML authentication if it is not authenticated
 */
public class AuthnRequestService extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(AuthnRequestService.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    	logger.info("In doGet() of SPAuthnRequestService");
    	logger.info("Have to do user authentication");
    	logger.info("Create and send SAML AuthnRequest to IdP");
    	AuthnRequestHandler authnRequestHandler = new AuthnRequestHandler();
    	authnRequestHandler.redirectUserForAuthentication(response);
    }
}