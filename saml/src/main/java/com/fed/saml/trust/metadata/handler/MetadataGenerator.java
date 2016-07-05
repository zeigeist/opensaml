package com.fed.saml.trust.metadata.handler;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import com.fed.saml.sp.protocol.utils.Constants;
import com.fed.saml.sp.protocol.utils.CryptoUtil;
import com.fed.saml.sp.protocol.utils.SAMLUtil;
import com.fed.saml.trust.metadata.objects.AssertionConsumerService;
import com.fed.saml.trust.metadata.objects.EncryptionMethod;
import com.fed.saml.trust.metadata.objects.EntityDescriptor;
import com.fed.saml.trust.metadata.objects.KeyDescriptor;
import com.fed.saml.trust.metadata.objects.KeyInfo;
import com.fed.saml.trust.metadata.objects.SPSSODescriptor;
import com.fed.saml.trust.metadata.objects.X509Data;
import com.fed.saml.trust.metadata.objects.X509IssuerSerial;

public class MetadataGenerator {
     
     private static final String ACS_URL = Constants.PROTOCOL + "://" + 
  		   								   SAMLUtil.getConfigProperties().get(Constants.PROP_HOSTNAME) + ":" + 
  		   								   SAMLUtil.getConfigProperties().get(Constants.PROP_PORT) + 
  		   								   Constants.ASSERTION_CONSUMER_SERVICE;
     //	No slo support
     //private static final String SLO_POST_URL = "http://localhost:8080/saml/sp/slo";
     
     private static final String KEY_DESCRIPTOR_SIGNING = "signing";
     private static final String KEY_DESCRIPTOR_ENCYPTION = "encryption";

     private static final String ENCRYPTION_METHOD_RSA = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
     private static final String ENCRYPTION_METHOD_AES_128 = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
	    
     private static final String ARTIFACT_BINDING_FQDN = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
     
     private static final String POST_BINDING_FQDN = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
     
     private static final String PROTOCOL_SUPPORT_ENUMERATION = "urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol";
     
     public String generateMetadata() {
    	 String metadata = null;
    	 X509Certificate x509Cert = null;
    	 try {
    		 x509Cert = (X509Certificate) CryptoUtil.readKeystoreFromFile(Constants.SP_KEY_STORE_PATH, 
    				 Constants.SP_KEY_STORE_PASSWORD).getCertificate(Constants.SP_KEY_ALIAS);
    	 } catch (KeyStoreException e2) {
    		 e2.printStackTrace();
    	 }
    	 
    	 if (x509Cert != null) {
    		 X509IssuerSerial x509IssuerSerial = new X509IssuerSerial();
    		 x509IssuerSerial.setX509IssuerName(x509Cert.getIssuerDN().getName());
    		 x509IssuerSerial.setX509SerialNumber(x509Cert.getSerialNumber());

    		 X509Data x509Data = new X509Data();
    		 try {
    			 x509Data.setX509Certificate(x509Cert.getEncoded());
    		 } catch (CertificateEncodingException e1) {
    			 e1.printStackTrace();
    		 }
    		 x509Data.setX509IssuerSerial(x509IssuerSerial);
    		 x509Data.setX509SubjectName(x509Cert.getSubjectDN().getName());

    		 KeyInfo keyInfo = new KeyInfo();
    		 keyInfo.setX509Data(x509Data);

    		 KeyDescriptor keyDescriptorSigning = new KeyDescriptor();
    		 keyDescriptorSigning.setUse(KEY_DESCRIPTOR_SIGNING);
    		 keyDescriptorSigning.setKeyInfo(keyInfo);


    		 EncryptionMethod encryptionMethodRSA = new EncryptionMethod();
    		 encryptionMethodRSA.setAlgorithm(ENCRYPTION_METHOD_RSA);
    		 EncryptionMethod encryptionMethodAES128 = new EncryptionMethod();
    		 encryptionMethodAES128.setAlgorithm(ENCRYPTION_METHOD_AES_128);

    		 KeyDescriptor keyDescriptorEncryption = new KeyDescriptor();
    		 keyDescriptorEncryption.setUse(KEY_DESCRIPTOR_ENCYPTION);
    		 keyDescriptorEncryption.setKeyInfo(keyInfo);
    		 keyDescriptorEncryption.getEncryptionMethod().add(encryptionMethodRSA);
    		 keyDescriptorEncryption.getEncryptionMethod().add(encryptionMethodAES128);

    		 /*SingleLogoutService singleLogoutServiceRedirect = new SingleLogoutService();
    		 singleLogoutServiceRedirect.setBinding(REDIRECT_BINDING_FQDN);
    		 singleLogoutServiceRedirect.setLocation(SLO_POST_URL);
    		 singleLogoutServiceRedirect.setResponseLocation(SLO_POST_URL);

    		 SingleLogoutService singleLogoutServicePost = new SingleLogoutService();
    		 singleLogoutServicePost.setBinding(POST_BINDING_FQDN);
    		 singleLogoutServicePost.setLocation(SLO_POST_URL);
    		 singleLogoutServicePost.setResponseLocation(SLO_POST_URL);*/

    		 AssertionConsumerService assertionConsumerServicePost = new AssertionConsumerService();
    		 assertionConsumerServicePost.setBinding(POST_BINDING_FQDN);
    		 assertionConsumerServicePost.setIndex(new BigInteger("0"));
    		 assertionConsumerServicePost.setIsDefault(true);
    		 assertionConsumerServicePost.setLocation(ACS_URL);
    		 
    		 SPSSODescriptor spSSODescriptor = new SPSSODescriptor();
    		 spSSODescriptor.setProtocolSupportEnumeration(PROTOCOL_SUPPORT_ENUMERATION);
    		 spSSODescriptor.setWantAssertionsSigned(false);
    		 spSSODescriptor.setAuthnRequestsSigned(false);
    		 spSSODescriptor.getKeyDescriptor().add(keyDescriptorSigning);
    		 spSSODescriptor.getKeyDescriptor().add(keyDescriptorEncryption);
    		 //spSSODescriptor.getSingleLogoutService().add(singleLogoutServiceRedirect);
    		 //spSSODescriptor.getSingleLogoutService().add(singleLogoutServicePost);
    		 spSSODescriptor.setAssertionConsumerService(assertionConsumerServicePost);

    		 EntityDescriptor entityDescriptor = new EntityDescriptor();
    		 entityDescriptor.setID(SAMLUtil.getRandomNumber());
    		 entityDescriptor.setEntityID(SAMLUtil.getConfigProperties().get(Constants.PROP_SP_ENTITY_ID));
    		 entityDescriptor.setValidUntil(SAMLUtil.getValidUntilDate());
    		 entityDescriptor.setSPSSODescriptor(spSSODescriptor);

    		 JAXBContext jaxbContext;
    		 try {
    			 jaxbContext = JAXBContext.newInstance(EntityDescriptor.class);
    			 metadata = asString(jaxbContext, entityDescriptor);
    		 } catch (JAXBException e) {
    			 e.printStackTrace();
    		 }
    	 }
    	 System.out.println("Metadata generated.");

    	 return metadata;
     }	
	
	private String asString(JAXBContext pContext, Object pObject) throws JAXBException {
		java.io.StringWriter sw = new StringWriter();

		Marshaller marshaller = pContext.createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

		marshaller.marshal(pObject, sw);
		return sw.toString();
	}
}
