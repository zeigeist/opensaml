package com.fed.saml.sp.protocol.utils;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.opensaml.xml.util.Base64;

import sun.security.provider.X509Factory;

public class CryptoUtil {
	
	public static X509Certificate convertStringToCertificate(String certStr) throws CertificateException {
        byte [] decoded = Base64.decode(certStr.replaceAll(X509Factory.BEGIN_CERT, "").replaceAll(X509Factory.END_CERT, ""));
        return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
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