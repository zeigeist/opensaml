package com.fed.saml.sp.protocol.authn.services;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.authn.handlers.ArtifactResolveRequestHandler;
import com.fed.saml.sp.protocol.authn.handlers.ArtifactResponseHandler;
import com.fed.saml.sp.protocol.authn.handlers.ProtectedResourceHandler;
import com.fed.saml.sp.protocol.utils.OpenSAMLUtils;

public class AssertionConsumerService extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(AssertionConsumerService.class);
    
    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        logger.info("Artifact received from IdP");
        ArtifactResolveRequestHandler artifactResolveRequestHandler = new ArtifactResolveRequestHandler();
        ArtifactResponseHandler artifactResponseHandler = new ArtifactResponseHandler();
        ProtectedResourceHandler protectedResourceHandler = new ProtectedResourceHandler();
        
        Artifact artifact = artifactResolveRequestHandler.buildArtifactFromRequest(req);
        
        // validate the SAML artifact query
        if(artifact != null && !artifact.isNil()) {
            logger.info("Artifact: " + artifact.getArtifact());
      
	        // build ArtifactResolve request
	        ArtifactResolve artifactResolve = artifactResolveRequestHandler.buildArtifactResolve(artifact);
	        artifactResolveRequestHandler.signArtifactResolve(artifactResolve);
	        logger.info("ArtifactResolve: ");
	        OpenSAMLUtils.logSAMLObject(artifactResolve);
	
	        // send ArtifactResolve request and wait for ArtifactResponse via SOAP
	        logger.info("Sending ArtifactResolve request to IdP via SOAP");
	        ArtifactResponse artifactResponse = artifactResolveRequestHandler.sendAndReceiveArtifactResolve(artifactResolve);
	        logger.info("ArtifactResponse received from IdP via SOAP");
	        logger.info("ArtifactResponse: ");
	        OpenSAMLUtils.logSAMLObject(artifactResponse);
	        
	        // validate ArtifactResponse
	        Response response = (Response)artifactResponse.getMessage();
	        StatusCode statusCode = response.getStatus().getStatusCode();
	        if(StatusCode.SUCCESS_URI.equals(statusCode.getValue())) {
	        	List<EncryptedAssertion> encryptedAssertionList= response.getEncryptedAssertions();
			    if (!encryptedAssertionList.isEmpty()) {
			    	
			    	// decrypt and check integrity of ArtifactResponse 
			        EncryptedAssertion encryptedAssertion = artifactResponseHandler.getEncryptedAssertion(artifactResponse);
			        Assertion assertion = artifactResponseHandler.decryptAssertion(encryptedAssertion);
			        artifactResponseHandler.verifyAssertionSignature(assertion);
			        logger.info("Decrypted Assertion: ");
			        OpenSAMLUtils.logSAMLObject(assertion);
			
			        // print saml message attributes
			        artifactResponseHandler.logAuthenticationInstant(assertion);
			        artifactResponseHandler.logAuthenticationMethod(assertion);
			        artifactResponseHandler.logSAMLAttributes(assertion);

			        String nameIdValue = artifactResponseHandler.getNameIdOfPrincipal(assertion);
			        req.setAttribute("subject_id", nameIdValue); // set nameid as subject_id in request
			        
			        // prepare to redirect to requested resource
			        protectedResourceHandler.setAuthenticatedFlagInSession(req);
			        protectedResourceHandler.redirectToRequestedResource(req, resp);
			    } else {
			    	List<Assertion> assertionList = response.getAssertions(); 
			    	if (!assertionList.isEmpty()) {
				    	
			    		// decrypt and check integrity of ArtifactResponse 
			    		artifactResponseHandler.verifyAssertionSignature(assertionList.get(0));
				        logger.info("Decrypted Assertion: ");
				        OpenSAMLUtils.logSAMLObject(assertionList.get(0));
				
				        // print saml message attributes
				        artifactResponseHandler.logAuthenticationInstant(assertionList.get(0));
				        artifactResponseHandler.logAuthenticationMethod(assertionList.get(0));
				        artifactResponseHandler.logSAMLAttributes(assertionList.get(0));

				        String nameIdValue = artifactResponseHandler.getNameIdOfPrincipal(assertionList.get(0));
				        req.setAttribute("subject_id", nameIdValue);
				        
				        // prepare to redirect to requested resource
				        protectedResourceHandler.setAuthenticatedFlagInSession(req);
				        protectedResourceHandler.redirectToRequestedResource(req, resp);
				    }
			    }
	        } else {
	        	logger.info("SAML Artifact Response Received with failure StatusCode: "+ statusCode.getValue());
	    		resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Received artifact is NOT equal to artifact sent by IdP");
	        }
        } else {
        	logger.info("Artifact not received from IdP via query");
    		resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Artifact not received from IdP via query");
        }
    }

    
}
