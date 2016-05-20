package com.fed.saml.protocol.sp;

/**
 * Created by Privat on 4/7/14.
 */
public class SPConstants {
	protected static final String SP_ENTITY_ID = "TestSP";
    protected static final String AUTHENTICATED_SESSION_ATTRIBUTE = "authenticated";
    protected static final String GOTO_URL_SESSION_ATTRIBUTE = "gotoURL";
    protected static final String ASSERTION_CONSUMER_SERVICE = "http://localhost:8080/saml/sp/assertionconsumer";
    protected static final String ARTIFACT_RESOLUTION_SERVICE = "http://localhost:8080/saml/idp/artifactresolution";
    protected static final String SSO_SERVICE = "http://localhost:8080/saml/idp/sso";

}
