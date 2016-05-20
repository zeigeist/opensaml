package com.fed.saml.testsp;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This servlet acts as the resource that the access filter is protecting
 */
public class TestSPService extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(TestSPService.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    	logger.info("In doGet() of TestSPService");
    	logger.info("Finally reached TestSP");
        resp.setContentType("text/html");
        resp.getWriter().append("<h1>You are now at the requested resource</h1>");
        resp.getWriter().append("This is the protected resource. You are authenticated");
    }
}
