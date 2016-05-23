package com.fed.saml.protocol.sp;

public class SPConstants {
	protected static final String SP_ENTITY_ID = "http://localhost:8080/saml/sp";
	
    protected static final String AUTHENTICATED_SESSION_ATTRIBUTE = "authenticated";
    protected static final String REQUESTED_RESOURCE_SESSION_ATTRIBUTE = "requestedResource";
    
    protected static final String ASSERTION_CONSUMER_SERVICE = "http://localhost:8080/saml/sp/assertionconsumer";
    
    protected static final String ARTIFACT_RESOLUTION_SERVICE = "http://localhost:8090/idp/profile/SAML2/SOAP/ArtifactResolution";
    protected static final String SSO_SERVICE = "http://localhost:8090/idp/profile/SAML2/Redirect/SSO";
    
    protected static final String SP_KEY_ALIAS = "spkey";
    protected static final String IDP_KEY_ALIAS = "localidp";
    protected static final String KEY_STORE_PASSWORD = "password";
    protected static final String KEY_STORE_ENTRY_PASSWORD = "password";
    protected static final String SP_KEY_STORE_PATH = "/SPKeystore.jks";
    protected static final String IDP_KEY_STORE_PATH = "/IdPKeystore.jks";

}
