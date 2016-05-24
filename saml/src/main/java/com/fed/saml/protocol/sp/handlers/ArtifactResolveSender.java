package com.fed.saml.protocol.sp.handlers;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.protocol.sp.utils.Constants;
import com.fed.saml.protocol.sp.utils.Credentials;
import com.fed.saml.protocol.sp.utils.OpenSAMLUtils;

public class ArtifactResolveSender {
    private static Logger logger = LoggerFactory.getLogger(ArtifactResolveSender.class);
    
    public static Artifact buildArtifactFromRequest(final HttpServletRequest req) {
        Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
        artifact.setArtifact(req.getParameter("SAMLart"));
        return artifact;
    }
    
    public static ArtifactResolve buildArtifactResolve(final Artifact artifact) {
        ArtifactResolve artifactResolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);

        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(Constants.SP_ENTITY_ID);
        artifactResolve.setIssuer(issuer);

        artifactResolve.setIssueInstant(new DateTime());

        artifactResolve.setID(OpenSAMLUtils.generateSecureRandomId());

        artifactResolve.setDestination(Constants.ARTIFACT_RESOLUTION_SERVICE);

        artifactResolve.setArtifact(artifact);

        return artifactResolve;
    }
    
    public static void signArtifactResolve(ArtifactResolve artifactResolve) {
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
    public static ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve) {
        try {
            Envelope envelope = OpenSAMLUtils.wrapInSOAPEnvelope(artifactResolve);

            HttpClientBuilder clientBuilder = new HttpClientBuilder();
            HttpSOAPClient soapClient = new HttpSOAPClient(clientBuilder.buildClient(), new BasicParserPool());

            BasicSOAPMessageContext soapContext = new BasicSOAPMessageContext();
            soapContext.setOutboundMessage(envelope);

            soapClient.send(Constants.ARTIFACT_RESOLUTION_SERVICE, soapContext);

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
