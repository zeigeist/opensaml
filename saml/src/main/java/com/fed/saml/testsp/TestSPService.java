package com.fed.saml.testsp;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.utils.Constants;

public class TestSPService extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(TestSPService.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    	logger.info("In doGet() of TestSPService");
    	logger.info("Finally reached TestSP");
    	
    	// receive USER_ID_SESSION_ATTR_NAME from session.
    	String userId = (String) req.getSession().getAttribute(Constants.USER_ID_SESSION_ATTR_NAME);
    	
        resp.setContentType("text/html");
        resp.getWriter().append("<h1>*** SAML Authentication Successful ***</h1>");
        resp.getWriter().append("Hi <b>" + userId + "</b>, You are authenticated by SAML IdP and now at the requested resource at SP.");
    }
}
