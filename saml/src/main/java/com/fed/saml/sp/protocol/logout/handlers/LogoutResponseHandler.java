package com.fed.saml.sp.protocol.logout.handlers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipException;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogoutResponseHandler {
	private static Logger logger = LoggerFactory.getLogger(LogoutResponseHandler.class);

	public String decodeLogoutRequestXML(String encodedRequestXmlString) throws Exception {
		String uncompressed = null;
		try {
			// URL decode
			// No need to URL decode: auto decoded by request.getParameter()
			// method
			// Base64 decode
			Base64 base64Decoder = new Base64();
			byte[] xmlBytes = encodedRequestXmlString.getBytes("UTF-8");
			byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

			//logger.info("base64DecodedByteArray:: " + new String(base64DecodedByteArray));
			
			// Uncompress the LogoutRequest data using a stream decompressor, as
			// suggested in discussions
			// of the Google Apps Api's group.
			try {
				uncompressed = new String(inflate(base64DecodedByteArray, true));
			} catch (ZipException e) {
				uncompressed = new String(inflate(base64DecodedByteArray, false));
			}
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			throw new Exception("Error decoding AuthnRequest: " + "Check decoding scheme - " + e.getMessage());

		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception("Error decoding AuthnRequest: " + "Check decoding scheme - " + e.getMessage());

		}
		logger.info("uncompressed:: " + uncompressed);
		return uncompressed;
	}
	
	private static byte[] altInflate(byte[] bytes) throws IOException {
		ByteArrayInputStream bais = null;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		InflaterInputStream iis = null;
		byte[] buf = new byte[1024];
		try {
			// if DEFLATE fails, then attempt to unzip the byte array according
			// to
			// zlib (rfc 1950)
			bais = new ByteArrayInputStream(bytes);
			iis = new InflaterInputStream(bais);
			buf = new byte[1024];
			int count = iis.read(buf); // PROBLEM
			while (count != -1) {
				baos.write(buf, 0, count);
				count = iis.read(buf);
			}
			return baos.toByteArray();
		} catch (IOException ex) {
			throw ex;
		} finally {
			if (iis != null)
				try {
					iis.close();
				} catch (IOException ex2) {
				}
			if (baos != null) {
				try {
					baos.close();
				} catch (IOException ex2) {
				}
			}
		}
	}

	private static byte[] inflate(byte[] bytes, boolean nowrap) throws IOException {
		Inflater decompressor = null;
		ByteArrayOutputStream out = null;
		try {
			decompressor = new Inflater(nowrap);
			decompressor.setInput(bytes);
			out = new ByteArrayOutputStream(bytes.length);
			byte[] buf = new byte[1024];
			while (!decompressor.finished()) {
				try {
					int count = decompressor.inflate(buf); // PROBLEM
					out.write(buf, 0, count);
					// added check to avoid loops
					if (count == 0) {
						return altInflate(bytes);
					}
				} catch (DataFormatException e) {
					return altInflate(bytes);

				} catch (Exception e) {
					return altInflate(bytes);
				} catch (Throwable e) {
					return altInflate(bytes);
				}
			}
			return out.toByteArray();
		} finally {
			if (decompressor != null)
				decompressor.end();
			try {
				if (out != null)
					out.close();
			} catch (IOException ioe) {
				/* ignore */
			}
		}
	}

	
}
