package com.fed.saml.sp.protocol.authn.services;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.utils.Constants;

/**
 * The filter intercepts the user and start the SAML authentication if it is not authenticated
 */
public class AccessFilterService implements Filter {
    private static Logger logger = LoggerFactory.getLogger(AccessFilterService.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Configuration.validateJCEProviders();
        Configuration.validateNonSunJAXP();
        
        for (Provider jceProvider : Security.getProviders()) {
            logger.info(jceProvider.getInfo());
        }

        try {
            logger.info("Bootstrapping in init() of AccessFilterService");
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new RuntimeException("Bootstrapping failed");
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
    		FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest)request;
        HttpServletResponse httpServletResponse = (HttpServletResponse)response;
        logger.info("In doFilter() of AccessFilterService");
       
        if (httpServletRequest.getSession().getAttribute(Constants.AUTHENTICATED_SESSION_ATTRIBUTE) != null) {
        	logger.info("SAML User Authentication is done");
        	// set the user_id cookie
        	setSPCookies(httpServletRequest, httpServletResponse);
            chain.doFilter(request, response);            
        } else {
        	logger.info("Have to do SAML user authentication");
        	logger.info("Forward request to AuthnRequestService");
        	setRequestedResourceInSession(httpServletRequest);
			request.getRequestDispatcher("sp/authnrequestservice").forward(request, response);
        }
        return;
    }
    
    // to prevent infinite looping between filter and 'sp/authnrequestservice'
    private void setRequestedResourceInSession(HttpServletRequest request) {
        request.getSession().setAttribute(Constants.REQUESTED_RESOURCE_SESSION_ATTRIBUTE, 
        		request.getRequestURL().toString());
    }
    
    private void setSPCookies(HttpServletRequest request, HttpServletResponse response) {
    	Cookie userCookie = new Cookie(Constants.USER_ID_SESSION_ATTR_NAME, 
    			request.getSession().getAttribute(Constants.USER_ID_SESSION_ATTR_NAME).toString());
    	// save the cookie
    	logger.info(userCookie.getName() + " | " + userCookie.getValue());
    	response.addCookie(userCookie);
    }
    
    @Override
    public void destroy() {

    }
}