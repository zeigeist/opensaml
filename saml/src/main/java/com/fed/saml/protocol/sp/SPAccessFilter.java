package com.fed.saml.protocol.sp;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
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
import org.opensaml.xml.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.protocol.utils.OpenSAMLUtils;

/**
 * The filter intercepts the user and start the SAML authentication if it is not authenticated
 */
public class SPAccessFilter implements Filter {
    private static Logger logger = LoggerFactory.getLogger(SPAccessFilter.class);

    public void init(FilterConfig filterConfig) throws ServletException {
        Configuration.validateJCEProviders();
        Configuration.validateNonSunJAXP();
        
        for (Provider jceProvider : Security.getProviders()) {
            logger.info(jceProvider.getInfo());
        }

        try {
            logger.info("Bootstrapping in init() of SPAccessFilter");
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new RuntimeException("Bootstrapping failed");
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest)request;
        HttpServletResponse httpServletResponse = (HttpServletResponse)response;
        logger.info("In doFilter() of SPAccessFilter");
        if (httpServletRequest.getSession().getAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE) != null) {
        	logger.info("SAML User Authentication is done");
            chain.doFilter(request, response);
        } else {
        	logger.info("Have to do SAML user authentication");
            setGotoURLOnSession(httpServletRequest);
            redirectUserForAuthentication(httpServletResponse);
        }
    }

    private void setGotoURLOnSession(HttpServletRequest request) {
        request.getSession().setAttribute(SPConstants.GOTO_URL_SESSION_ATTRIBUTE, request.getRequestURL().toString());
    }

    private void redirectUserForAuthentication(HttpServletResponse httpServletResponse) {
        AuthnRequest authnRequest = buildAuthnRequest();
        redirectUserWithRequest(httpServletResponse, authnRequest);

    }

    private void redirectUserWithRequest(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {
        HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(httpServletResponse, true);
        BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context = new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
        context.setPeerEntityEndpoint(getIPDEndpoint());
        context.setOutboundSAMLMessage(authnRequest);
        context.setOutboundMessageTransport(responseAdapter);
        context.setOutboundSAMLMessageSigningCredential(SPCredentials.getCredential());

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
        logger.info("AuthnRequest: ");
        OpenSAMLUtils.logSAMLObject(authnRequest);

        try {
        	logger.info("Sending AuthnRequest to IdPSSOService");
            encoder.encode(context); // send to IdPSSOService
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private AuthnRequest buildAuthnRequest() {
        AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setDestination(getIPDSSODestination());
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerEndpoint());
        authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
        authnRequest.setIssuer(buildIssuer());
        authnRequest.setNameIDPolicy(buildNameIdPolicy());
        authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());

        return authnRequest;
    }
    private RequestedAuthnContext buildRequestedAuthnContext() {
        RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        AuthnContextClassRef passwordAuthnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

        return requestedAuthnContext;

    }

    private NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);

        nameIDPolicy.setFormat(NameIDType.TRANSIENT);

        return nameIDPolicy;
    }

    private Issuer buildIssuer() {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(getSPIssuerValue());

        return issuer;
    }

    private String getSPIssuerValue() {
        return SPConstants.SP_ENTITY_ID;
    }

    private String getSPNameQualifier() {
        return SPConstants.SP_ENTITY_ID;
    }

    private String getAssertionConsumerEndpoint() {
        return SPConstants.ASSERTION_CONSUMER_SERVICE;
    }

    private String getIPDSSODestination() {
        return SPConstants.SSO_SERVICE;
    }

    private Endpoint getIPDEndpoint() {
        SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation(getIPDSSODestination());

        return endpoint;
    }


    public void destroy() {

    }
}