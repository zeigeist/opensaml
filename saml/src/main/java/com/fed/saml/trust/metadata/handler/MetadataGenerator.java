package com.fed.saml.trust.metadata.handler;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import com.fed.saml.security.CryptoSecurity;
import com.fed.saml.trust.metadata.objects.AssertionConsumerService;
import com.fed.saml.trust.metadata.objects.EncryptionMethod;
import com.fed.saml.trust.metadata.objects.EntityDescriptor;
import com.fed.saml.trust.metadata.objects.KeyDescriptor;
import com.fed.saml.trust.metadata.objects.KeyInfo;
import com.fed.saml.trust.metadata.objects.SPSSODescriptor;
import com.fed.saml.trust.metadata.objects.SingleLogoutService;
import com.fed.saml.trust.metadata.objects.X509Data;
import com.fed.saml.trust.metadata.objects.X509IssuerSerial;
import com.fed.saml.utils.MetadataUtils;

public class MetadataGenerator {
	public String generateMetadata() {
		
		KeyPair keyPair = CryptoSecurity.generateKeyPair();
		X509Certificate x509Cert = CryptoSecurity.generateSelfSignedCertificate("CN=Test, L=Santa Clara, ST=CA, C=USA",
				keyPair, 10, "SHA1withRSA");

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
		keyDescriptorSigning.setUse("signing");
		keyDescriptorSigning.setKeyInfo(keyInfo);

		EncryptionMethod encryptionMethodRSA = new EncryptionMethod();
		encryptionMethodRSA.setAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
		EncryptionMethod encryptionMethodAES128 = new EncryptionMethod();
		encryptionMethodAES128.setAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");

		KeyDescriptor keyDescriptorEncryption = new KeyDescriptor();
		keyDescriptorEncryption.setUse("encryption");
		keyDescriptorEncryption.setKeyInfo(keyInfo);
		keyDescriptorEncryption.getEncryptionMethod().add(encryptionMethodRSA);
		keyDescriptorEncryption.getEncryptionMethod().add(encryptionMethodAES128);

		SingleLogoutService singleLogoutServiceRedirect = new SingleLogoutService();
		singleLogoutServiceRedirect.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		singleLogoutServiceRedirect.setLocation("https://service.example.org/sp/slo");
		singleLogoutServiceRedirect.setResponseLocation("https://service.example.org/sp/slo");

		SingleLogoutService singleLogoutServicePost = new SingleLogoutService();
		singleLogoutServicePost.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		singleLogoutServicePost.setLocation("https://service.example.org/sp/slo");
		singleLogoutServicePost.setResponseLocation("https://service.example.org/sp/slo");

		AssertionConsumerService assertionConsumerService = new AssertionConsumerService();
		assertionConsumerService.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		assertionConsumerService.setIndex(new BigInteger("0"));
		assertionConsumerService.setIsDefault(true);
		assertionConsumerService.setLocation("https://service.example.org/sp/sso");

		SPSSODescriptor spSSODescriptor = new SPSSODescriptor();
		spSSODescriptor.setProtocolSupportEnumeration(
				"urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol");
		spSSODescriptor.setWantAssertionsSigned(false);
		spSSODescriptor.setAuthnRequestsSigned(false);
		spSSODescriptor.getKeyDescriptor().add(keyDescriptorSigning);
		spSSODescriptor.getKeyDescriptor().add(keyDescriptorEncryption);
		spSSODescriptor.getSingleLogoutService().add(singleLogoutServiceRedirect);
		spSSODescriptor.getSingleLogoutService().add(singleLogoutServicePost);
		spSSODescriptor.setAssertionConsumerService(assertionConsumerService);

		EntityDescriptor entityDescriptor = new EntityDescriptor();
		entityDescriptor.setID(MetadataUtils.getRandomNumber());
		entityDescriptor.setEntityID("https://service.example.org/sp");
		entityDescriptor.setValidUntil(MetadataUtils.getValidUntilDate());
		entityDescriptor.setSPSSODescriptor(spSSODescriptor);

		JAXBContext jaxbContext;
		String metadata = null;
		try {
			jaxbContext = JAXBContext.newInstance(EntityDescriptor.class);
			metadata = asString(jaxbContext, entityDescriptor);
		} catch (JAXBException e) {
			e.printStackTrace();
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
