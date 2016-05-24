package com.fed.saml.protocol.sp.handlers;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fed.saml.protocol.sp.utils.Constants;

public class ProtectedResourceHandler {
    private static Logger logger = LoggerFactory.getLogger(ProtectedResourceHandler.class);

    public static void setAuthenticatedFlagInSession(HttpServletRequest req) {
        req.getSession().setAttribute(Constants.AUTHENTICATED_SESSION_ATTRIBUTE, true);
    }

	public static void redirectToRequestedResource(HttpServletRequest req, HttpServletResponse resp) {
		// set subject_id from request to session, since we are redirecting to /testsp. 
		req.getSession().setAttribute("subject_id", req.getAttribute("subject_id"));
		
        String requestedResource = (String)req.getSession().getAttribute(Constants.REQUESTED_RESOURCE_SESSION_ATTRIBUTE);
        logger.info("Redirecting to requested resource: " + requestedResource);
        try {
            resp.sendRedirect(requestedResource);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
