package com.fed.saml.protocol.sp;

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

import com.fed.saml.protocol.utils.OpenSAMLUtils;

public class SPAssertionConsumerService extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(SPAssertionConsumerService.class);
    
    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        logger.info("Artifact received from IdPSSOService");
        Artifact artifact = buildArtifactFromRequest(req);
        
        // validate the SAML artifact query
        if(artifact != null && !artifact.isNil()) {
            logger.info("Artifact: " + artifact.getArtifact());
      
	        // build ArtifactResolve request
	        ArtifactResolve artifactResolve = buildArtifactResolve(artifact);
	        signArtifactResolve(artifactResolve);
	        logger.info("ArtifactResolve: ");
	        OpenSAMLUtils.logSAMLObject(artifactResolve);
	
	        // send ArtifactResolve request and wait for ArtifactResponse via SOAP
	        logger.info("Sending ArtifactResolve request to IdPArtifactResolutionService via SOAP");
	        ArtifactResponse artifactResponse = sendAndReceiveArtifactResolve(artifactResolve);
	        logger.info("ArtifactResponse received from IdPArtifactResolutionService via SOAP");
	        logger.info("ArtifactResponse: ");
	        OpenSAMLUtils.logSAMLObject(artifactResponse);
	        
	        // validate ArtifactResponse
	        Response response = (Response)artifactResponse.getMessage();
	        StatusCode statusCode = response.getStatus().getStatusCode();
	        if(StatusCode.SUCCESS_URI.equals(statusCode.getValue())) {
	        	List<EncryptedAssertion> encryptedAssertionList= response.getEncryptedAssertions();
			    if (!encryptedAssertionList.isEmpty()) {
			    	
			    	// decrypt and check integrity of ArtifactResponse 
			        EncryptedAssertion encryptedAssertion = getEncryptedAssertion(artifactResponse);
			        Assertion assertion = decryptAssertion(encryptedAssertion);
			        verifyAssertionSignature(assertion);
			        logger.info("Decrypted Assertion: ");
			        OpenSAMLUtils.logSAMLObject(assertion);
			
			        // print saml message attributes
			        logAssertionAttributes(assertion);
			        logAuthenticationInstant(assertion);
			        logAuthenticationMethod(assertion);

			        // prepare to redirect to requested resource
			        setAuthenticatedFlagInSession(req);
			        redirectToRequestedResource(req, resp);
			    } else {
			    	List<Assertion> assertionList = response.getAssertions(); 
			    	if (!assertionList.isEmpty()) {
				    	
			    		// decrypt and check integrity of ArtifactResponse 
				        verifyAssertionSignature(assertionList.get(0));
				        logger.info("Decrypted Assertion: ");
				        OpenSAMLUtils.logSAMLObject(assertionList.get(0));
				
				        // print saml message attributes
				        logAssertionAttributes(assertionList.get(0));
				        logAuthenticationInstant(assertionList.get(0));
				        logAuthenticationMethod(assertionList.get(0));
				
				        // prepare to redirect to requested resource
				        setAuthenticatedFlagInSession(req);
				        redirectToRequestedResource(req, resp);
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

    private Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(SPCredentials.getSPCredential(SPConstants.SP_KEY_ALIAS));

        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);

        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new RuntimeException(e);
        }
    }

    private void verifyAssertionSignature(Assertion assertion) {
        if (!assertion.isSigned()) {
            throw new RuntimeException("The SAML Assertion was not signed");
        }

        try {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(assertion.getSignature());

            SignatureValidator sigValidator = new SignatureValidator(SPCredentials.getIdPCredential(SPConstants.IDP_KEY_ALIAS));

            sigValidator.validate(assertion.getSignature());

            logger.info("SAML Assertion signature verified");
        } catch (ValidationException e) {
        	e.printStackTrace();
        	logger.error(e.getMessage());
            throw new RuntimeException(e);
        }

    }

    private void signArtifactResolve(ArtifactResolve artifactResolve) {
        Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
        signature.setSigningCredential(SPCredentials.getSPCredential(SPConstants.SP_KEY_ALIAS));
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        artifactResolve.setSignature(signature);

        try {
            Configuration.getMarshallerFactory().getMarshaller(artifactResolve).marshall(artifactResolve);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private void setAuthenticatedFlagInSession(HttpServletRequest req) {
        req.getSession().setAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE, true);
    }

    private void redirectToRequestedResource(HttpServletRequest req, HttpServletResponse resp) {
        String requestedResource = (String)req.getSession().getAttribute(SPConstants.REQUESTED_RESOURCE_SESSION_ATTRIBUTE);
        logger.info("Redirecting to requested resource: " + requestedResource);
        try {
            resp.sendRedirect(requestedResource);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void logAuthenticationMethod(Assertion assertion) {
        logger.info("Authentication method: " + assertion.getAuthnStatements().get(0)
                .getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
    }

    private void logAuthenticationInstant(Assertion assertion) {
        logger.info("Authentication instant: " + assertion.getAuthnStatements().get(0).getAuthnInstant());
    }

    private void logAssertionAttributes(Assertion assertion) {
    	if(assertion.getAttributeStatements().size() > 0) {
    		for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
    				logger.info("Attribute name: " + attribute.getName());
    			for (XMLObject attributeValue : attribute.getAttributeValues()) {
    				logger.info("Attribute value: " + ((XSString) attributeValue).getValue());
    			}
    		}
    	} else {
    		logger.info("No Attributes from received Assertion");
    	}
    }

    private EncryptedAssertion getEncryptedAssertion(ArtifactResponse artifactResponse) {
        Response response = (Response)artifactResponse.getMessage();
        return response.getEncryptedAssertions().get(0);
    }

    private ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve) {
        try {
            Envelope envelope = OpenSAMLUtils.wrapInSOAPEnvelope(artifactResolve);

            HttpClientBuilder clientBuilder = new HttpClientBuilder();
            HttpSOAPClient soapClient = new HttpSOAPClient(clientBuilder.buildClient(), new BasicParserPool());

            BasicSOAPMessageContext soapContext = new BasicSOAPMessageContext();
            soapContext.setOutboundMessage(envelope);

            soapClient.send(SPConstants.ARTIFACT_RESOLUTION_SERVICE, soapContext);

            Envelope soapResponse = (Envelope)soapContext.getInboundMessage();
            return (ArtifactResponse)soapResponse.getBody().getUnknownXMLObjects().get(0);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (SOAPException e) {
            throw new RuntimeException(e);
        }
    }

    private Artifact buildArtifactFromRequest(final HttpServletRequest req) {
        Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
        artifact.setArtifact(req.getParameter("SAMLart"));
        return artifact;
    }

    private ArtifactResolve buildArtifactResolve(final Artifact artifact) {
        ArtifactResolve artifactResolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);

        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(SPConstants.SP_ENTITY_ID);
        artifactResolve.setIssuer(issuer);

        artifactResolve.setIssueInstant(new DateTime());

        artifactResolve.setID(OpenSAMLUtils.generateSecureRandomId());

        artifactResolve.setDestination(SPConstants.ARTIFACT_RESOLUTION_SERVICE);

        artifactResolve.setArtifact(artifact);

        return artifactResolve;
    }

}
