package com.fed.saml.protocol.sp.utils;

public class Constants {
	public static final String SP_ENTITY_ID = "http://localhost:8080/saml/sp";
	
	public static final String AUTHENTICATED_SESSION_ATTRIBUTE = "authenticated";
	public static final String REQUESTED_RESOURCE_SESSION_ATTRIBUTE = "requestedResource";
    
	public static final String ASSERTION_CONSUMER_SERVICE = "http://localhost:8080/saml/sp/assertionconsumer";
    
    public static final String ARTIFACT_RESOLUTION_SERVICE = "http://localhost:8090/idp/profile/SAML2/SOAP/ArtifactResolution";
    public static final String SSO_SERVICE = "http://localhost:8090/idp/profile/SAML2/Redirect/SSO";
    
    public static final String SP_KEY_ALIAS = "spkey";
    public static final String IDP_KEY_ALIAS = "localidp";
    public static final String KEY_STORE_PASSWORD = "password";
    public static final String KEY_STORE_ENTRY_PASSWORD = "password";
    public static final String SP_KEY_STORE_PATH = "/SPKeystore.jks";
    public static final String IDP_KEY_STORE_PATH = "/IdPKeystore.jks";

}
