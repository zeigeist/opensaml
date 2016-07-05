package com.fed.saml.sp.protocol.logout.handlers;

import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.SessionIndex;
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

public class LogoutRequestHandler {
    private static Logger logger = LoggerFactory.getLogger(LogoutRequestHandler.class);
    
    public void redirectUserForLogout(HttpServletResponse httpServletResponse) {
        LogoutRequest logoutRequest = buildLogoutRequest();
        redirectUserWithRequest(httpServletResponse, logoutRequest);
    }

    private void redirectUserWithRequest(HttpServletResponse httpServletResponse, LogoutRequest logoutRequest) {
        HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(httpServletResponse, true);
        BasicSAMLMessageContext<SAMLObject, LogoutRequest, SAMLObject> context = new BasicSAMLMessageContext<SAMLObject, LogoutRequest, SAMLObject>();
        context.setPeerEntityEndpoint(getIPDEndpoint());
        context.setOutboundSAMLMessage(logoutRequest);
        context.setOutboundMessageTransport(responseAdapter);
        context.setOutboundSAMLMessageSigningCredential(CryptoUtil.getSPCredential(Constants.SP_KEY_ALIAS));

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
        logger.info("LogoutRequest: ");
        OpenSAMLUtils.logSAMLObject(logoutRequest);

        try {
        	logger.info("Sending LogoutRequest to IdP");
            encoder.encode(context); // send to IdP
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private LogoutRequest buildLogoutRequest() {
    	LogoutRequest logoutRequest = OpenSAMLUtils.buildSAMLObject(LogoutRequest.class);
    	logoutRequest.setIssueInstant(new DateTime());
    	logoutRequest.setDestination(getIPDSLODestination());
    	logoutRequest.setID(OpenSAMLUtils.generateSecureRandomId());
    	logoutRequest.setIssuer(buildIssuer());
    	
    	SessionIndex sessionIndexElement = OpenSAMLUtils.buildSAMLObject(SessionIndex.class);
    	//sessionIndexElement.setSessionIndex(ArtifactResponseHandler.sessionIndex);
    	logoutRequest.getSessionIndexes().add(sessionIndexElement);
    	 
    	NameID nameID = OpenSAMLUtils.buildSAMLObject(NameID.class);
    	nameID.setSPProvidedID("http://localhost:8080/saml/sp");
    	nameID.setFormat(NameIDType.TRANSIENT);
    	nameID.setNameQualifier("https://ganesh.mac.com/idp/shibboleth");
    	nameID.setValue("alice");
    	logoutRequest.setNameID(nameID);
        return logoutRequest;
    }

    private Issuer buildIssuer() {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(getSPIssuerValue());

        return issuer;
    }

    private String getSPIssuerValue() {
        return SAMLUtil.getConfigProperties().get(Constants.PROP_SP_ENTITY_ID);
    }

    private String getIPDSLODestination() {
    	Map<String, String> idpConfig = IdPPartnerConfig.getIdPConfig(); // get IdPConfig from metadata

        return idpConfig.get(Constants.KEY_IDP_SLO_REDIRECT);
    }

    private Endpoint getIPDEndpoint() {
        SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation(getIPDSLODestination());

        return endpoint;
    }
}