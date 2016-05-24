package com.fed.saml.protocol.sp.handlers;

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

import com.fed.saml.protocol.sp.utils.Constants;
import com.fed.saml.protocol.sp.utils.Credentials;
import com.fed.saml.protocol.sp.utils.OpenSAMLUtils;

public class ArtifactResponseProcessor {
    private static Logger logger = LoggerFactory.getLogger(ArtifactResponseProcessor.class);
 
    public static EncryptedAssertion getEncryptedAssertion(ArtifactResponse artifactResponse) {
        Response response = (Response)artifactResponse.getMessage();
        return response.getEncryptedAssertions().get(0);
    }
    
    public static Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(Credentials.getSPCredential(Constants.SP_KEY_ALIAS));

        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);

        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new RuntimeException(e);
        }
    }

    public static void verifyAssertionSignature(Assertion assertion) {
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
    
    public static void logAssertionAttributes(Assertion assertion) {
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
    
    public static void logAuthenticationInstant(Assertion assertion) {
        logger.info("Authentication instant: " + assertion.getAuthnStatements().get(0).getAuthnInstant());
    }

    public static void logAuthenticationMethod(Assertion assertion) {
        logger.info("Authentication method: " + assertion.getAuthnStatements().get(0)
                .getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
    }
    
    public static String getNameIdOfPrincipal(Assertion assertion) {
    	String nameIdValue = assertion.getSubject().getNameID().getValue();
        
    	logger.info("NameID format: " + assertion.getSubject().getNameID().getFormat());
        logger.info("NameID value: " + nameIdValue);
        logger.info("IdP Name Qualifier: " + assertion.getSubject().getNameID().getNameQualifier());
        logger.info("SP Name Qualifier: " + assertion.getSubject().getNameID().getSPNameQualifier());
        
        return nameIdValue;
    }
}
