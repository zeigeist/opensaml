package com.fed.saml.sp.protocol.authn.services;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.authn.handlers.SAMLArtifactResolveRequest;
import com.fed.saml.sp.protocol.authn.handlers.ProtectedResourceHandler;
import com.fed.saml.sp.protocol.authn.handlers.SAMLAssertion;
import com.fed.saml.sp.protocol.authn.handlers.SAMLAuthnRequest;
import com.fed.saml.sp.protocol.authn.handlers.SAMLNameID;
import com.fed.saml.sp.protocol.authn.handlers.SAMLResponse;
import com.fed.saml.sp.protocol.utils.Constants;
import com.fed.saml.sp.protocol.utils.OpenSAMLUtils;

public class AssertionConsumerService extends HttpServlet {
	private static Logger logger = LoggerFactory.getLogger(AssertionConsumerService.class);
	
	private ProtectedResourceHandler protectedResourceHandler = new ProtectedResourceHandler();
	
	@Override
	protected void doGet(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse)
			throws ServletException, IOException {
		processRequest(httpRequest, httpResponse);
	}

	@Override
	protected void doPost(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) 
			throws ServletException, IOException {
		processRequest(httpRequest, httpResponse);
	}	
	
	protected void processRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse) 
			throws ServletException, IOException {
		
		if ("get".equalsIgnoreCase(httpRequest.getMethod())) {
			logger.info("Artifact Query received from IdP");
			SAMLArtifactResolveRequest artifactResolveRequestHandler = new SAMLArtifactResolveRequest();
			artifactResolveRequestHandler.processResponse(httpRequest, httpResponse);
		} else if ("post".equalsIgnoreCase(httpRequest.getMethod())) {
			logger.info("POST Response received from IdP");
			SAMLResponse samlResponse = new SAMLResponse();
			samlResponse.processResponse(httpRequest, httpResponse);
		} 
		
		// prepare to redirect to requested resource
		protectedResourceHandler.setAuthenticatedFlagInSession(httpRequest);
		protectedResourceHandler.redirectToRequestedResource(httpRequest, httpResponse);
	}
}