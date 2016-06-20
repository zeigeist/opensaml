package com.fed.saml.sp.protocol.authn.handlers;

import org.opensaml.saml2.core.Assertion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLNameID {
    private static Logger logger = LoggerFactory.getLogger(SAMLNameID.class);

    private Assertion assertion;
    
    public SAMLNameID(Assertion assertion) {
    	this.assertion = assertion;
    }
    
	public String getNameIdValue() {        
        logger.info("Name Id Format: " + assertion.getSubject().getNameID().getValue());
        return assertion.getSubject().getNameID().getValue();
    }
	
	public String getNameIdFormat() {
        logger.info("Name Id Format: " + assertion.getSubject().getNameID().getFormat());
        return assertion.getSubject().getNameID().getFormat();
    }
	
	public String getNameQualifier() {
        logger.info("IdP Name Qualifier: " + assertion.getSubject().getNameID().getNameQualifier());
        return assertion.getSubject().getNameID().getNameQualifier();
    }
	
	public String getSPNameQualifier() {
        logger.info("SP Name Qualifier: " + assertion.getSubject().getNameID().getSPNameQualifier());
        return assertion.getSubject().getNameID().getSPNameQualifier();
    }
}
