package com.fed.saml.trust.cot.idp;

import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.X509Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.utils.Constants;
import com.fed.saml.sp.protocol.utils.CryptoUtil;
import com.fed.saml.sp.protocol.utils.SAMLUtil;

public class IdPPartnerConfig {
	
	private static Logger logger = LoggerFactory.getLogger(IdPPartnerConfig.class);
	private static Map<String, String> idpConfig = null;
	private static FilesystemMetadataProvider idpMetaDataProvider = null;
	private static EntityDescriptor idpEntityDescriptor = null;
	
	static {
		try {
			idpMetaDataProvider = new FilesystemMetadataProvider(
					new File(SAMLUtil.getConfigProperties().get(Constants.PROP_IDP_METADATA_LOCATION)));
			idpMetaDataProvider.setRequireValidMetadata(true);
			idpMetaDataProvider.setParserPool(new BasicParserPool());
			idpMetaDataProvider.initialize();
			idpEntityDescriptor = idpMetaDataProvider.getEntityDescriptor(SAMLUtil.getConfigProperties().get(Constants.PROP_IDP_ENTITY_ID));
		} catch (MetadataProviderException e) {
			e.printStackTrace();
		}
	}
	
    public static Map<String, String> getIdPConfig()  {
    	idpConfig = new HashMap<String, String>();
    	
    	// SSO services endpoints
    	for (SingleSignOnService singleSignOnService : idpEntityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getSingleSignOnServices()) { 
    		if (singleSignOnService.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
    			logger.info(singleSignOnService.getLocation());
    			idpConfig.put(Constants.KEY_IDP_SSO_POST, singleSignOnService.getLocation());
    		}
    		
    		if (singleSignOnService.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
    			logger.info(singleSignOnService.getLocation());
    			idpConfig.put(Constants.KEY_IDP_SSO_REDIRECT, singleSignOnService.getLocation());
    		}
    	}
    	
    	// SLO services endpoints
    	for (SingleLogoutService singleLogoutService : idpEntityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getSingleLogoutServices()) { 
    		if (singleLogoutService.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
    			logger.info(singleLogoutService.getLocation());
    			idpConfig.put(Constants.KEY_IDP_SLO_POST, singleLogoutService.getLocation());
    		}
    		
    		if (singleLogoutService.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
    			logger.info(singleLogoutService.getLocation());
    			idpConfig.put(Constants.KEY_IDP_SLO_REDIRECT, singleLogoutService.getLocation());
    		}
    	}
    	
    	// Artifact Resolution services endpoint
    	String artifactResolutionServiceURL = null;
    	for (ArtifactResolutionService ars : 
    		idpEntityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getArtifactResolutionServices()) {
    		if (ars.getBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
    			artifactResolutionServiceURL = ars.getLocation();
    			logger.info(artifactResolutionServiceURL);
    			idpConfig.put(Constants.KEY_IDP_ARTIFACT_RESOLUTION, artifactResolutionServiceURL);
    		}
    	}
    	
    	return idpConfig;
    }
  
    public static Credential getCertificateFromMetaData() throws CertificateException {
		for (KeyDescriptor key : idpEntityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getKeyDescriptors()) {
			X509Data x509 = key.getKeyInfo().getX509Datas().get(0);
			org.opensaml.xml.signature.X509Certificate x509Cert = x509.getX509Certificates().get(0);
			logger.info("Found Certificate: "+ x509Cert.getValue().toString());
			
			String certString = CryptoUtil.convertCertToPemFormat(x509Cert.getValue());
		
			X509Certificate certificate = CryptoUtil.convertStringToCertificate(certString);
			
			// convert X509Certificate to BasicX509Credential
	        BasicX509Credential credential = new BasicX509Credential();
	        credential.setEntityCertificate(certificate);

			return credential;
		}
		return null;
	}
}
