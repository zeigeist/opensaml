package com.fed.saml.protocol.idp;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.protocol.utils.OpenSAMLUtils;

/**
 * Created by Privat on 4/6/14.
 */
public class IdPSSOService extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(IdPSSOService.class);
    private static final String ASSERTION_CONSUMER_SERVICE = "http://localhost:8080/saml/sp/assertionconsumer";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    	// validate the SAML AuthnRequest
    	
        logger.info("AuthnRequest recieved in doGet() of IdPSSOService");
        logger.info("Have to do Login for user");
        logger.info("Redirect request to LoginService");
        resp.sendRedirect("/saml/web/login"); // AuthnRequest received, redirect to LoginService
    }

    @Override
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        logger.info("Return from LoginService");
        logger.info("In doPost() of IdPSSOService");
        logger.info("Redirect to SPAssertionConsumerService");
        
        // retrieve the userid from response
        //int userid = (int) req.getAttribute("userid");

        // generate SAML artifact from 3 components and persist it
        String samlArtifact = OpenSAMLUtils.getSAML2ArtifactType0004(IdPConstants.ENDPOINT_INDEX, IdPConstants.SOURCE_ID, IdPConstants.MSG_HANDLE);
        
        // send the generated artifact to SPAssertionConsumerService
        //resp.sendRedirect(ASSERTION_CONSUMER_SERVICE + "?SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D"); // reply with saml artifact to SPAssertionConsumerService 
        resp.sendRedirect(ASSERTION_CONSUMER_SERVICE + "?SAMLart=" + samlArtifact);
    }
}
