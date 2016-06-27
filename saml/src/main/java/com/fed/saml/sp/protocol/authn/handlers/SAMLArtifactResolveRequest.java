package com.fed.saml.sp.protocol.authn.handlers;

import java.io.IOException;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.utils.Constants;
import com.fed.saml.sp.protocol.utils.Credentials;
import com.fed.saml.sp.protocol.utils.OpenSAMLUtils;
import com.fed.saml.sp.protocol.utils.SAMLUtil;
import com.fed.saml.trust.cot.idp.IdPPartnerConfig;

public class SAMLArtifactResolveRequest {
    private static Logger logger = LoggerFactory.getLogger(SAMLArtifactResolveRequest.class);
    
    public void processResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException {
		// receive SAMLResponse from httRequest
    	Artifact artifact = buildArtifactFromRequest(httpRequest);
		boolean responseValid = false;
		// validate the SAML artifact query
		if (artifact != null && !artifact.isNil()) {
			logger.info("Artifact: " + artifact.getArtifact());

			// build ArtifactResolve request
			ArtifactResolve artifactResolve = buildArtifactResolve(artifact);
			signArtifactResolve(artifactResolve);
			logger.info("ArtifactResolve: ");
			OpenSAMLUtils.logSAMLObject(artifactResolve);

			// send ArtifactResolve request and wait for ArtifactResponse via
			// SOAP
			logger.info("Sending ArtifactResolve request to IdP via SOAP");
			ArtifactResponse artifactResponse = sendAndReceiveArtifactResolve(artifactResolve);
			logger.info("ArtifactResponse received from IdP via SOAP");
			logger.info("ArtifactResponse: ");
			OpenSAMLUtils.logSAMLObject(artifactResponse);

			SAMLResponse samlResponse = new SAMLResponse();

			// validate ArtifactResponse
			Response response = (Response) artifactResponse.getMessage();

			// validate the response
			if (response != null) {
				responseValid = samlResponse.validateResponse(response);
			}
			
			if (responseValid) {
				SAMLAssertion samlAssertion = new SAMLAssertion(response); 
				Assertion assertion = samlAssertion.getAssertionFromResponse();
				
				String nameIdValue = new SAMLNameID(assertion).getNameIdValue();
				httpRequest.setAttribute(Constants.USER_ID_SESSION_ATTR_NAME, nameIdValue); // set nameid as user_id in request
			} else {
				logger.info("Response error from IdP");
				httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Response error from IdP");
			}
		} else {
			logger.info("Artifact not received from IdP via query");
			httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Artifact not received from IdP via query");
		}
    }
    
    private Artifact buildArtifactFromRequest(final HttpServletRequest req) {
        Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
        artifact.setArtifact(req.getParameter("SAMLart"));
        return artifact;
    }
    
    private ArtifactResolve buildArtifactResolve(final Artifact artifact) {
    	Map<String, String> idpConfig = IdPPartnerConfig.getIdPConfig(); // get IdPConfig from metadata

        ArtifactResolve artifactResolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);

        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(SAMLUtil.getConfigProperties().get(Constants.PROP_SP_ENTITY_ID));
        artifactResolve.setIssuer(issuer);

        artifactResolve.setIssueInstant(new DateTime());

        artifactResolve.setID(OpenSAMLUtils.generateSecureRandomId());

        artifactResolve.setDestination(idpConfig.get(Constants.KEY_IDP_ARTIFACT_RESOLUTION));
        
        artifactResolve.setArtifact(artifact);

        return artifactResolve;
    }
    
    private void signArtifactResolve(ArtifactResolve artifactResolve) {
        Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
        signature.setSigningCredential(Credentials.getSPCredential(Constants.SP_KEY_ALIAS));
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        artifactResolve.setSignature(signature);

        try {
            Configuration.getMarshallerFactory().getMarshaller(artifactResolve).marshall(artifactResolve);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }
    
    private ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve) {
    	Map<String, String> idpConfig = IdPPartnerConfig.getIdPConfig(); // get IdPConfig from metadata

        try {
            Envelope envelope = OpenSAMLUtils.wrapInSOAPEnvelope(artifactResolve);

            HttpClientBuilder clientBuilder = new HttpClientBuilder();
            HttpSOAPClient soapClient = new HttpSOAPClient(clientBuilder.buildClient(), new BasicParserPool());

            BasicSOAPMessageContext soapContext = new BasicSOAPMessageContext();
            soapContext.setOutboundMessage(envelope);

            soapClient.send(idpConfig.get(Constants.KEY_IDP_ARTIFACT_RESOLUTION), soapContext);

            Envelope soapResponse = (Envelope)soapContext.getInboundMessage();
            return (ArtifactResponse)soapResponse.getBody().getUnknownXMLObjects().get(0);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (SOAPException e) {
            throw new RuntimeException(e);
        }
    }

}
