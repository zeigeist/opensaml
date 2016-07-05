package com.fed.saml.sp.protocol.utils;

public class Constants {

	public static final String ASSERTION_CONSUMER_SERVICE = "/saml/sp/assertionconsumer";
	public static final String POST_TEMPLATE = "/templates/saml2-post-binding.vm";
	public static final String PROTOCOL = "http";

	// properties from config.properties
	public static final String PROP_HOSTNAME = "hostname";
	public static final String PROP_PORT = "port";
	public static final String PROP_REQUEST_BINDING = "request_binding";
	public static final String PROP_RESPONSE_BINDING = "response_binding";
	public static final String PROP_NAMEID_TYPE = "nameid_type";
	public static final String PROP_SP_ENTITY_ID = "sp_entity_id";
	public static final String PROP_IDP_ENTITY_ID = "idp_entity_descriptor";
	public static final String PROP_IDP_METADATA_LOCATION = "idp_metadata_location";
	
	// session attributes
	public static final String AUTHENTICATED_SESSION_ATTRIBUTE = "authenticated";
	public static final String REQUESTED_RESOURCE_SESSION_ATTRIBUTE = "requestedResource";
   
	// SP certificate and key information
    public static final String SP_KEY_ALIAS = "spkey";
    public static final String SP_KEY_STORE_PASSWORD = "password";
    public static final String SP_KEY_STORE_ENTRY_PASSWORD = "password";
    public static final String SP_KEY_STORE_PATH = "/SPKeystore.jks";
    
    // for user session 
    public static final String USER_ID_SESSION_ATTR_NAME = "user_id";
    
    // IdP data from its metadata
    public static final String KEY_IDP_ARTIFACT_RESOLUTION = "idp_artifact_endpoint_key";
    public static final String KEY_IDP_SSO_REDIRECT = "idp_sso_redirect_key";
    public static final String KEY_IDP_SSO_POST = "idp_sso_post_key";
    public static final String KEY_IDP_SLO_REDIRECT = "idp_slo_redirect_key";
    public static final String KEY_IDP_SLO_POST = "idp_slo_post_key";
    public static final String KEY_IDP_CERTIFICATE = "idp_certificate_key";

}
