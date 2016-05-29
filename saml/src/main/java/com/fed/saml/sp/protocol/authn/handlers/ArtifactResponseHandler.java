package com.fed.saml.sp.protocol.authn.handlers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import com.fed.saml.sp.protocol.utils.Constants;
import com.fed.saml.sp.protocol.utils.Credentials;

public class ArtifactResponseHandler {
    private static Logger logger = LoggerFactory.getLogger(ArtifactResponseHandler.class);
 
    public EncryptedAssertion getEncryptedAssertion(ArtifactResponse artifactResponse) {
        Response response = (Response)artifactResponse.getMessage();
        return response.getEncryptedAssertions().get(0);
    }
    
    public Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
    	Assertion decryptedAssertion = null;
	    if(encryptedAssertion != null) {
	        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(Credentials.getSPCredential(Constants.SP_KEY_ALIAS));
	
	        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
	        decrypter.setRootInNewDocument(true);
	
	        try {
	            return decrypter.decrypt(encryptedAssertion);
	        } catch (DecryptionException e) {
	            throw new RuntimeException(e);
	        }
    	}
    	return decryptedAssertion;
    }

    public void verifyAssertionSignature(Assertion assertion) {
    	if(assertion != null) {
    		if (!assertion.isSigned()) {
    			throw new RuntimeException("The SAML Assertion was not signed");
    		}

	        try {
	            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
	            profileValidator.validate(assertion.getSignature());
	
	            SignatureValidator sigValidator = new SignatureValidator(Credentials.getIdPCredential(Constants.IDP_KEY_ALIAS));
	
	            sigValidator.validate(assertion.getSignature());
	
	            logger.info("SAML Assertion signature verified");
	        } catch (ValidationException e) {
	        	e.printStackTrace();
	        	logger.error(e.getMessage());
	            throw new RuntimeException(e);
	        }
    	}
    }
    
//    public void logAssertionAttributes(Assertion assertion) {
//    	if(assertion != null && assertion.getAttributeStatements().size() > 0) {
//    		for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
//    				logger.info("Attribute name: " + attribute.getName());
//    			for (XMLObject attributeValue : attribute.getAttributeValues()) {
//    				logger.info("Attribute value: " + ((XSString) attributeValue).getValue());
//    			}
//    		}
//    	} else {
//    		logger.info("No Attributes from received Assertion");
//    	}
//    }
    
    public void logAuthenticationInstant(Assertion assertion) {
        if (assertion != null && assertion.getAuthnStatements() != null) {
        	logger.info("Authentication instant: " + assertion.getAuthnStatements().get(0).getAuthnInstant());
        }
    }

    public void logAuthenticationMethod(Assertion assertion) {
        if (assertion != null && assertion.getAuthnStatements() != null) {
        	logger.info("Authentication method: " + assertion.getAuthnStatements().get(0)
                .getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
        }
    }
    
    public void logSAMLAttributes(Assertion assertion) {
        Map<String, String> results = new HashMap<String, String>();
        if (assertion != null && assertion.getAttributeStatements() != null) {

            List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();
            
            for (AttributeStatement statement : attributeStatementList) {
                List<Attribute> attributesList = statement.getAttributes();
                for (Attribute attribute : attributesList) {
                    Element value = attribute.getAttributeValues().get(0).getDOM();
                    String attributeValue = value.getTextContent();
                    results.put(attribute.getFriendlyName(), attributeValue);
                }
            }

        }
        logger.info("SAML Attributes: " + results);
    }

    public String getNameIdOfPrincipal(Assertion assertion) {
    	String nameIdValue = assertion.getSubject().getNameID().getValue();
        
    	logger.info("NameID format: " + assertion.getSubject().getNameID().getFormat());
        logger.info("NameID value: " + nameIdValue);
        logger.info("IdP Name Qualifier: " + assertion.getSubject().getNameID().getNameQualifier());
        logger.info("SP Name Qualifier: " + assertion.getSubject().getNameID().getSPNameQualifier());
        
        return nameIdValue;
    }
}
