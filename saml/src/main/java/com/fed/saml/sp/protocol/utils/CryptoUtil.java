package com.fed.saml.sp.protocol.utils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.xml.security.Criteria;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.util.Base64;

import sun.security.provider.X509Factory;

public class CryptoUtil {
	
	public static KeyStore readKeystoreFromFile(String pathToKeyStore, String keyStorePassword) {
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream inputStream = CryptoUtil.class.getResourceAsStream(pathToKeyStore);
            keystore.load(inputStream, keyStorePassword.toCharArray());
            inputStream.close();
            return keystore;
        } catch (Exception e) {
            throw new RuntimeException("Something went wrong reading keystore", e);
        }
    }
    
    public static Credential getSPCredential(String aliasName) {
    	Credential credential = null;
    	try {
            KeyStore keystore = readKeystoreFromFile(Constants.SP_KEY_STORE_PATH, 
            		Constants.SP_KEY_STORE_PASSWORD);
            Map<String, String> passwordMap = new HashMap<String, String>();
            passwordMap.put(aliasName, Constants.SP_KEY_STORE_ENTRY_PASSWORD);
            KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

            Criteria criteria = new EntityIDCriteria(aliasName);
            CriteriaSet criteriaSet = new CriteriaSet(criteria);

            credential = resolver.resolveSingle(criteriaSet);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new RuntimeException("Something went wrong reading credentials", e);
        }
        return credential;
    }
	public static X509Certificate convertStringToCertificate(String certStr) throws CertificateException {
        byte [] decoded = 
        		Base64.decode(certStr.replaceAll(X509Factory.BEGIN_CERT, "").replaceAll(X509Factory.END_CERT, ""));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
    }
    
    public static String convertCertToPemFormat(String cert) {
        return formatPEMString(X509Factory.BEGIN_CERT, X509Factory.END_CERT, cert);
    }
    
    public static String formatPEMString(final String head, final String foot, final String indata){
        StringBuilder pem = new StringBuilder(head);
        pem.append("\n");

        String data;
        if (indata != null) {
            data = indata.replaceAll("\\s+","");
        } else {
            data = "";
        }
        int lineLength = 64;
        int dataLen = data.length();
        int si = 0;
        int ei = lineLength;

        while (si < dataLen) {
            if (ei > dataLen) {
                ei = dataLen;
            }

            pem.append(data.substring(si, ei));
            pem.append("\n");
            si = ei;
            ei += lineLength;
        }

        pem.append(foot);

        return pem.toString();
    }
}