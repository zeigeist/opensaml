package com.fed.saml.sp.protocol.logout.services;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.logout.handlers.LogoutRequestHandler;

public class LogoutRequestService extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(LogoutRequestService.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    	logger.info("In doGet() of LogoutRequestService");
    	logger.info("Have to do logout");
    	logger.info("Create and send SAML LogoutRequest to IdP");
    	
    	LogoutRequestHandler logoutRequestHandler = new LogoutRequestHandler();
    	logoutRequestHandler.redirectUserForLogout(response);
    }


}
