package com.fed.saml.sp.protocol.authn.handlers;

import java.io.IOException;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.utils.Constants;
import com.fed.saml.sp.protocol.utils.CryptoUtil;
import com.fed.saml.sp.protocol.utils.OpenSAMLUtils;
import com.fed.saml.sp.protocol.utils.SAMLUtil;
import com.fed.saml.trust.cot.idp.IdPPartnerConfig;

public class SAMLAuthnRequest {
    private static Logger logger = LoggerFactory.getLogger(SAMLAuthnRequest.class);
    AuthnRequest authnRequest = null;
    
    public SAMLAuthnRequest() {
    	authnRequest = buildAuthnRequest();
    }
    
    public void sendAuthRequest(HttpServletResponse httpResponse) throws IOException {
    	// get binding configuration properties
    	String binding = SAMLUtil.getConfigProperties().get(Constants.PROP_REQUEST_BINDING);  
    	
    	if ("post".equals(binding)) {
		    logger.info("Sending AuthnRequest to IdP using POST");
		    postAuthRequest(httpResponse);
    	} else if ("redirect".equals(binding)) {
    		logger.info("Sending AuthnRequest to IdP using Redirect");
    		redirectAuthRequest(httpResponse);
    	}
    }
    
    public void redirectAuthRequest(HttpServletResponse httpResponse) {
        HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(httpResponse, true);
        BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context = 
        		new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
        context.setPeerEntityEndpoint(getIdPEndpoint());
        context.setOutboundSAMLMessage(authnRequest);
        context.setOutboundMessageTransport(responseAdapter);
        context.setOutboundSAMLMessageSigningCredential(CryptoUtil.getSPCredential(Constants.SP_KEY_ALIAS));

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
        logger.info("AuthnRequest: ");
        OpenSAMLUtils.logSAMLObject(authnRequest);

        try {
        	logger.info("Sending AuthnRequest to IdP using Redirect");
        	encoder.encode(context); // send to IdP
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }        
    }

    public void postAuthRequest(HttpServletResponse httpResponse) throws IOException {
    	HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(httpResponse, true);
        
    	BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context = 
    			new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
        context.setPeerEntityEndpoint(getIdPEndpoint());
        context.setOutboundSAMLMessage(authnRequest);
        context.setOutboundMessageTransport(responseAdapter);
        context.setOutboundSAMLMessageSigningCredential(CryptoUtil.getSPCredential(Constants.SP_KEY_ALIAS));
        context.setRelayState("relayState");

        // using velocity template engine, post the AuthRequest thru template form.
        VelocityEngine velocityEngine = new VelocityEngine();
		velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
		velocityEngine.setProperty("classpath.resource.loader.class", 
				"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
		velocityEngine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS, 
				"org.apache.velocity.runtime.log.NullLogSystem");
		
		try {
			velocityEngine.init();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	
		HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine, Constants.POST_TEMPLATE);
		logger.info("AuthnRequest: ");
        OpenSAMLUtils.logSAMLObject(authnRequest);
        
		try {
			logger.info("Sending AuthnRequest to IdP using POST");
			encoder.encode(context);
		} catch (MessageEncodingException e) {
			throw new RuntimeException(e);
		}        
    }

    /**
     * Build AuthnRequest based on HTTP-POST or HTTP-Redirect
     * @return
     */
    public AuthnRequest buildAuthnRequest() {
        AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setDestination(getIdPSSODestination());
        
        if ("post".equals(SAMLUtil.getConfigProperties().get(Constants.PROP_RESPONSE_BINDING))) {
        	authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        } 
        if ("artifact".equals(SAMLUtil.getConfigProperties().get(Constants.PROP_RESPONSE_BINDING))) {
        	authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
            authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerEndpoint());
        }
        
        authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
        authnRequest.setIssuer(buildIssuer());
        authnRequest.setNameIDPolicy(buildNameIdPolicy());
        //authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());

        return authnRequest;
    }
    
    /**
     * Build RequestedAuthnContext using Password Authn Context and Minimum comparison type.
     * @return
     */
    /*private RequestedAuthnContext buildRequestedAuthnContext() {
        AuthnContextClassRef passwordAuthnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

        RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

        return requestedAuthnContext;

    }*/

    /**
     * NameID supported are unspecified, emailAddrrss, transient, persistent.
     * @return
     */
    private NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);

        String givenNameIdType = SAMLUtil.getConfigProperties().get(Constants.PROP_NAMEID_TYPE);
        String resolvedNameIdType = null;
        
        switch (givenNameIdType) {
        case "unspecified":
        	resolvedNameIdType = NameIDType.UNSPECIFIED;
        case "emailAddress":
        	resolvedNameIdType = NameIDType.EMAIL;
        case "transient":
        	resolvedNameIdType = NameIDType.TRANSIENT;
        case "persistent":
        	resolvedNameIdType = NameIDType.PERSISTENT;
        default:
        	resolvedNameIdType = NameIDType.UNSPECIFIED;
        }
        
        nameIDPolicy.setFormat(resolvedNameIdType);
        return nameIDPolicy;
    }

    private Issuer buildIssuer() {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(getSPIssuerValue());

        return issuer;
    }

    private String getSPIssuerValue() {
        return SAMLUtil.getConfigProperties().get(Constants.PROP_SP_ENTITY_ID);
    }

    private String getSPNameQualifier() {
        return SAMLUtil.getConfigProperties().get(Constants.PROP_SP_ENTITY_ID);
    }

    private String getAssertionConsumerEndpoint() {
    	return Constants.PROTOCOL + "://" + 
    		   SAMLUtil.getConfigProperties().get(Constants.PROP_HOSTNAME) + ":" + 
    		   SAMLUtil.getConfigProperties().get(Constants.PROP_PORT) + 
    		   Constants.ASSERTION_CONSUMER_SERVICE;
    }

    private String getIdPSSODestination() {
    	Map<String, String> idpConfig = IdPPartnerConfig.getIdPConfig(); // get IdPConfig from metadata
    	
    	if ("post".equals(SAMLUtil.getConfigProperties().get(Constants.PROP_REQUEST_BINDING))) {
    		return idpConfig.get(Constants.KEY_IDP_SSO_POST);
    	} else if ("redirect".equals(SAMLUtil.getConfigProperties().get(Constants.PROP_REQUEST_BINDING))) {
    		return idpConfig.get(Constants.KEY_IDP_SSO_REDIRECT);
    	}
		return null;
    }

    private Endpoint getIdPEndpoint() {
        SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
        
        if ("post".equals(SAMLUtil.getConfigProperties().get(Constants.PROP_REQUEST_BINDING))) {
        	endpoint.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        } else if ("redirect".equals(SAMLUtil.getConfigProperties().get(Constants.PROP_REQUEST_BINDING))) {
        	endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        }
        
        endpoint.setLocation(getIdPSSODestination());

        return endpoint;
    }
}