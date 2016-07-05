package com.fed.saml.sp.protocol.authn.handlers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.util.encoders.Base64;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.fed.saml.sp.protocol.utils.Constants;

public class SAMLResponse {
	private static Logger logger = LoggerFactory.getLogger(SAMLResponse.class);

	public SAMLResponse() {

	}
	
	public void processResponse(HttpServletRequest httpRequest, 
			HttpServletResponse httpResponse) throws IOException {
		// receive SAMLResponse from httRequest
		String responseMessage = httpRequest.getParameter("SAMLResponse");
		boolean responseValid = false;
		
		Response response = getResponseObject(responseMessage);
					
		// validate the response
		if (response != null) {
			responseValid = validateResponse(response);
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
	}
	
	public boolean validateResponse(Response response) {
		StatusCode statusCode = response.getStatus().getStatusCode();
		if (StatusCode.SUCCESS_URI.equals(statusCode.getValue())) {
			logger.info("SAML Response Received with Success StatusCode: " + statusCode.getValue());
			return true;
		} else {
			logger.info("SAML Response Received with failure StatusCode: " + statusCode.getValue());
			return false;
		}
	}

	private Response getResponseObject(String responseMessage) {
		Response response = null;
		ByteArrayInputStream is = null;
		try {
			is = new ByteArrayInputStream(decodeResponseInBytes(responseMessage));
		} catch (Exception e1) {
			e1.printStackTrace();
		}

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder docBuilder = null;
		try {
			docBuilder = documentBuilderFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e1) {
			e1.printStackTrace();
		}

		Document document = null;
		try {
			document = docBuilder.parse(is);
		} catch (SAXException e1) {
			e1.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		Element element = document.getDocumentElement();
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		XMLObject responseXmlObj = null;
		try {
			responseXmlObj = unmarshaller.unmarshall(element);
			response = (Response) responseXmlObj;
		} catch (UnmarshallingException e1) {
			e1.printStackTrace();
		}

		return response;
	}

	private byte[] decodeResponseInBytes(String encodedString) throws Exception {
		byte[] base64DecodedByteArray = null;
		try {
			byte[] xmlBytes = encodedString.getBytes("UTF-8");
			base64DecodedByteArray = Base64.decode(xmlBytes);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			throw new Exception("Error decoding Response: " + "Check decoding scheme - " + e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception("Error decoding Response: " + "Check decoding scheme - " + e.getMessage());
		}
		logger.info("DecodedString:: " + new String(base64DecodedByteArray));
		return base64DecodedByteArray;
	}
}
