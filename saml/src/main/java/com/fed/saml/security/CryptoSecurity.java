package com.fed.saml.security;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

import org.apache.commons.io.IOUtils;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class CryptoSecurity {
	private static final String ASYMMETRIC_ALGO = "RSA";
	private static final String ARTIFACT_LOCATION = "/tmp/saml";
	private static final String KEY_PAIR_LOCATION = ARTIFACT_LOCATION + "/keypair.key";
	private static final String PUBLIC_KEY_LOCATION = ARTIFACT_LOCATION + "/public.key";
	private static final String PRIVATE_KEY_LOCATION = ARTIFACT_LOCATION + "/private.key";	

	public static KeyPair generateKeyPair() {
		new File(ARTIFACT_LOCATION).mkdir();
		
		KeyPair keyPair = getKeyPair();
		if(keyPair != null) {
			System.out.println("Keypair already available.");
			return keyPair;
		}
		
		System.out.println("Keypair not available, so generate it.");
		KeyPairGenerator keyGen = null;
		KeyFactory keyFactory = null;
		try {
			keyGen = KeyPairGenerator.getInstance(ASYMMETRIC_ALGO);
			keyFactory = KeyFactory.getInstance(ASYMMETRIC_ALGO);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		keyGen.initialize(1024);		
		keyPair = keyGen.genKeyPair();		
		
		RSAPublicKeySpec pub = null;
		RSAPrivateKeySpec priv = null;
		try {
			pub = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
			priv = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		
		saveKeyPair(KEY_PAIR_LOCATION, keyPair);
		saveKey(PUBLIC_KEY_LOCATION,  pub.getModulus(), pub.getPublicExponent());
		saveKey(PRIVATE_KEY_LOCATION, priv.getModulus(), priv.getPrivateExponent());

		return keyPair;
	}
	
	protected static KeyPair getKeyPair()  {
	    InputStream in = null;
	    ObjectInputStream oin = null;
	    KeyPair keyPair = null;	    
	    File keyPairFile = new File(KEY_PAIR_LOCATION);
	    if (keyPairFile.exists() && !keyPairFile.isDirectory()) { 		   		   
		    try {  	
				in = new FileInputStream(KEY_PAIR_LOCATION);				    	
	    	} catch (FileNotFoundException e) {			
				e.printStackTrace();
	    	}
		    try {
		    	oin = new ObjectInputStream(new BufferedInputStream(in));
		    	keyPair = (KeyPair) oin.readObject();
		    } catch (IOException | ClassNotFoundException e) {
		    	e.printStackTrace();
		    } finally {
		    	IOUtils.closeQuietly(oin);
		    }
	    }
		return keyPair;
	}
	
	private static void saveKeyPair(String fileName, KeyPair keyPair) {
		
		ObjectOutputStream oout = null;
		try {
			oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
			oout.writeObject(keyPair);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			IOUtils.closeQuietly(oout);
		}
	}
	
	private static void saveKey(String fileName, BigInteger mod, BigInteger exp) {
		ObjectOutputStream oout = null;
		try {
			oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
			oout.writeObject(mod);
			oout.writeObject(exp);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			IOUtils.closeQuietly(oout);
		}
	}
		
	protected static Key getKey(int keyType)  {
	    InputStream in = null;
	    ObjectInputStream oin = null;
	    Key key = null;	    
	    try {
	    	if (keyType == 1) {	
	    		File pubKeyFile = new File(PUBLIC_KEY_LOCATION);
	    	    if (pubKeyFile.exists() && !pubKeyFile.isDirectory()) { 		   		 
	    	    	in = new FileInputStream(PUBLIC_KEY_LOCATION);
	    	    }
	    	} else {
	    		File privKeyFile = new File(PRIVATE_KEY_LOCATION);
	    	    if (privKeyFile.exists() && !privKeyFile.isDirectory()) { 	
	    	    	in = new FileInputStream(PRIVATE_KEY_LOCATION);
	    	    }
	    	}
    	} catch (FileNotFoundException e) {			
			e.printStackTrace();
    	}
	    try {
	    	oin = new ObjectInputStream(new BufferedInputStream(in));
	        BigInteger m = (BigInteger) oin.readObject();
	        BigInteger e = (BigInteger) oin.readObject();
	        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
	        KeyFactory fact = KeyFactory.getInstance(ASYMMETRIC_ALGO);
	        key = fact.generatePublic(keySpec);
	    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | ClassNotFoundException e) {
	    	e.printStackTrace();
	    } finally {
	    	IOUtils.closeQuietly(oin);
	    }
		return key;
	}
	
	public static X509Certificate generateSelfSignedCertificate(String dn, KeyPair pair, int days,
			String algorithm) {

		PrivateKey privkey = pair.getPrivate();
		X509CertInfo info = new X509CertInfo();
		Date from = new Date();
		Date to = new Date(from.getTime() + days * 86400000l);
		CertificateValidity interval = new CertificateValidity(from, to);
		BigInteger sn = new BigInteger(64, new SecureRandom());
		X500Name owner;
		try {
			owner = new X500Name(dn);
			info.set(X509CertInfo.VALIDITY, interval);
			info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
			info.set(X509CertInfo.SUBJECT, owner);
			info.set(X509CertInfo.ISSUER, owner);
			info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
			info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
			AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
			info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
		} catch (CertificateException | IOException e) {
			e.printStackTrace();
		}

		// Sign the cert to identify the algorithm that's used.
		X509CertImpl cert = new X509CertImpl(info);
		try {
			cert.sign(privkey, algorithm);
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			e.printStackTrace();
		}

		/*
		 * // Update the algorithm, and resign. try { algo = (AlgorithmId)
		 * cert.get(X509CertImpl.SIG_ALG); } catch (CertificateParsingException
		 * e) { e.printStackTrace(); } try {
		 * info.set(CertificateAlgorithmId.NAME + "." +
		 * CertificateAlgorithmId.ALGORITHM, algo); } catch
		 * (CertificateException | IOException e) { e.printStackTrace(); } cert
		 * = new X509CertImpl(info); try { cert.sign(privkey, algorithm); }
		 * catch (InvalidKeyException | CertificateException |
		 * NoSuchAlgorithmException | NoSuchProviderException |
		 * SignatureException e) { e.printStackTrace(); }
		 */
		return cert;
	}
}