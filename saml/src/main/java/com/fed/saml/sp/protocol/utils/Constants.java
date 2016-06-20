package com.fed.saml.sp.protocol.utils;

public class Constants {
	
	public static final String PROP_REQUEST_BINDING = "request_binding";
	public static final String PROP_RESPONSE_BINDING = "response_binding";
	public static final String PROP_NAMEID_TYPE = "nameid_type";
	public static final String PROP_SP_ENTITY_ID = "sp_entity_id";
	
	public static final String AUTHENTICATED_SESSION_ATTRIBUTE = "authenticated";
	public static final String REQUESTED_RESOURCE_SESSION_ATTRIBUTE = "requestedResource";
    
	public static final String ASSERTION_CONSUMER_SERVICE = "http://localhost:8080/saml/sp/assertionconsumer";
    
    public static final String SP_KEY_ALIAS = "spkey";
    public static final String IDP_KEY_ALIAS = "localidp";
    public static final String KEY_STORE_PASSWORD = "password";
    public static final String KEY_STORE_ENTRY_PASSWORD = "password";
    public static final String SP_KEY_STORE_PATH = "/SPKeystore.jks";
    public static final String IDP_KEY_STORE_PATH = "/IdPKeystore.jks";
    
    public static final String USER_ID_SESSION_ATTR_NAME = "user_id";
    
    
    
    
    public static final String IDP_ARTIFACT_RESOLUTION_SERVICE = "http://localhost:8090/idp/profile/SAML2/SOAP/ArtifactResolution";
    public static final String IDP_SSO_SERVICE_REDIRECT = "http://localhost:8090/idp/profile/SAML2/Redirect/SSO";
    public static final String IDP_SSO_SERVICE_POST = "http://localhost:8090/idp/profile/SAML2/POST/SSO";

    public static final String IDP_SLO_SERVICE = "http://localhost:8090/idp/profile/SAML2/Redirect/SLO";

}
