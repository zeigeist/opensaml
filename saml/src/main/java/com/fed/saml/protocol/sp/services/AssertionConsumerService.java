package com.fed.saml.protocol.sp.services;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.protocol.sp.handlers.ArtifactResolveSender;
import com.fed.saml.protocol.sp.handlers.ArtifactResponseProcessor;
import com.fed.saml.protocol.sp.handlers.ProtectedResourceHandler;
import com.fed.saml.protocol.sp.utils.OpenSAMLUtils;

public class AssertionConsumerService extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(AssertionConsumerService.class);
    
    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        logger.info("Artifact received from IdP");
        Artifact artifact = ArtifactResolveSender.buildArtifactFromRequest(req);
        
        // validate the SAML artifact query
        if(artifact != null && !artifact.isNil()) {
            logger.info("Artifact: " + artifact.getArtifact());
      
	        // build ArtifactResolve request
	        ArtifactResolve artifactResolve = ArtifactResolveSender.buildArtifactResolve(artifact);
	        ArtifactResolveSender.signArtifactResolve(artifactResolve);
	        logger.info("ArtifactResolve: ");
	        OpenSAMLUtils.logSAMLObject(artifactResolve);
	
	        // send ArtifactResolve request and wait for ArtifactResponse via SOAP
	        logger.info("Sending ArtifactResolve request to IdP via SOAP");
	        ArtifactResponse artifactResponse = ArtifactResolveSender.sendAndReceiveArtifactResolve(artifactResolve);
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
			        EncryptedAssertion encryptedAssertion = ArtifactResponseProcessor.getEncryptedAssertion(artifactResponse);
			        Assertion assertion = ArtifactResponseProcessor.decryptAssertion(encryptedAssertion);
			        ArtifactResponseProcessor.verifyAssertionSignature(assertion);
			        logger.info("Decrypted Assertion: ");
			        OpenSAMLUtils.logSAMLObject(assertion);
			
			        // print saml message attributes
			        ArtifactResponseProcessor.logAssertionAttributes(assertion);
			        ArtifactResponseProcessor.logAuthenticationInstant(assertion);
			        ArtifactResponseProcessor.logAuthenticationMethod(assertion);
			        String nameIdValue = ArtifactResponseProcessor.getNameIdOfPrincipal(assertion);
			        req.setAttribute("subject_id", nameIdValue); // set nameid as subject_id in request
			        
			        // prepare to redirect to requested resource
			        ProtectedResourceHandler.setAuthenticatedFlagInSession(req);
			        ProtectedResourceHandler.redirectToRequestedResource(req, resp);
			    } else {
			    	List<Assertion> assertionList = response.getAssertions(); 
			    	if (!assertionList.isEmpty()) {
				    	
			    		// decrypt and check integrity of ArtifactResponse 
			    		ArtifactResponseProcessor.verifyAssertionSignature(assertionList.get(0));
				        logger.info("Decrypted Assertion: ");
				        OpenSAMLUtils.logSAMLObject(assertionList.get(0));
				
				        // print saml message attributes
				        ArtifactResponseProcessor.logAssertionAttributes(assertionList.get(0));
				        ArtifactResponseProcessor.logAuthenticationInstant(assertionList.get(0));
				        ArtifactResponseProcessor.logAuthenticationMethod(assertionList.get(0));
				        String nameIdValue = ArtifactResponseProcessor.getNameIdOfPrincipal(assertionList.get(0));
				        req.setAttribute("subject_id", nameIdValue);
				        
				        // prepare to redirect to requested resource
				        ProtectedResourceHandler.setAuthenticatedFlagInSession(req);
				        ProtectedResourceHandler.redirectToRequestedResource(req, resp);
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
