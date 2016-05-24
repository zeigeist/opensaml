package com.fed.saml.protocol.sp.utils;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.xml.security.Criteria;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;

public class Credentials {

    public static KeyStore readKeystoreFromFile(String pathToKeyStore, String keyStorePassword) {
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream inputStream = Credentials.class.getResourceAsStream(pathToKeyStore);
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
            KeyStore keystore = readKeystoreFromFile(Constants.SP_KEY_STORE_PATH, Constants.KEY_STORE_PASSWORD);
            Map<String, String> passwordMap = new HashMap<String, String>();
            passwordMap.put(aliasName, Constants.KEY_STORE_ENTRY_PASSWORD);
            KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

            Criteria criteria = new EntityIDCriteria(aliasName);
            CriteriaSet criteriaSet = new CriteriaSet(criteria);

            credential = resolver.resolveSingle(criteriaSet);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new RuntimeException("Something went wrong reading credentials", e);
        }
        return credential;
    }
    
    public static Credential getIdPCredential(String aliasName) {
    	Credential credential = null;
    	try {
            KeyStore keystore = readKeystoreFromFile(Constants.IDP_KEY_STORE_PATH, Constants.KEY_STORE_PASSWORD);
            Map<String, String> passwordMap = new HashMap<String, String>();
            //passwordMap.put(aliasName, SPConstants.KEY_STORE_ENTRY_PASSWORD);
            KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

            Criteria criteria = new EntityIDCriteria(aliasName);
            CriteriaSet criteriaSet = new CriteriaSet(criteria);

            credential = resolver.resolveSingle(criteriaSet);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new RuntimeException("Something went wrong reading credentials", e);
        }
        return credential;
    }
}
