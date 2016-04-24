package com.fed.saml.trust.metadata.handler;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

import com.fed.saml.trust.metadata.handler.MetadataGenerator;

public class MetadataServlet extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String metadata;

	public void init() throws ServletException {
		// Do required initialization
		//message = "Metadata going to publish soon!";
		
	}

	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		metadata = new MetadataGenerator().generateMetadata();
		// Set response content type
		response.setContentType("text/xml");
		// Actual logic goes here.
		PrintWriter out = response.getWriter();
		out.println(metadata);
	}

	public void destroy() {
		// do nothing.
	}
}