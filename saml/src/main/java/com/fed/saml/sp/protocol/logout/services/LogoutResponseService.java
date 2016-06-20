package com.fed.saml.sp.protocol.logout.services;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.logout.handlers.LogoutResponseHandler;

public class LogoutResponseService extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(LogoutResponseService.class);
    
    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        logger.info("LogoutResponse received from IdP");
                
        String responseMessage = req.getParameter("SAMLResponse");
        String sigAlg = req.getParameter("SigAlg");
        String signature = req.getParameter("Signature");

        LogoutResponseHandler logoutResponseHandler = new LogoutResponseHandler();
        try {
			logoutResponseHandler.decodeLogoutRequestXML(responseMessage);
		} catch (Exception e) {
			e.printStackTrace();
		}
    }
}
