package com.fed.saml.sp.protocol.authn.handlers;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.sp.protocol.utils.Constants;

public class ProtectedResourceHandler {
    private static Logger logger = LoggerFactory.getLogger(ProtectedResourceHandler.class);

    public void setAuthenticatedFlagInSession(HttpServletRequest req) {
        req.getSession().setAttribute(Constants.AUTHENTICATED_SESSION_ATTRIBUTE, true);
    }

	public void redirectToRequestedResource(HttpServletRequest req, HttpServletResponse resp) {
		// set USER_ID_SESSION_ATTR_NAME from request to session, since we are redirecting to /testsp. 
		req.getSession().setAttribute(Constants.USER_ID_SESSION_ATTR_NAME, req.getAttribute(Constants.USER_ID_SESSION_ATTR_NAME));
		
        String requestedResource = (String)req.getSession().getAttribute(Constants.REQUESTED_RESOURCE_SESSION_ATTRIBUTE);
        logger.info("Redirecting to requested resource: " + requestedResource);
        try {
            resp.sendRedirect(requestedResource);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
