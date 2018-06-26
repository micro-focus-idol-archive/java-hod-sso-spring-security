/*
 * Copyright 2015-2018 Micro Focus International plc.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Entry point for redirecting to a given SSO page, which will allow the user to authenticate
 */
public class SsoAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final String ssoEntryPage;

    /**
     * Creates a new SsoAuthenticationEntryPoint with the given SSO page
     * @param ssoEntryPage The URI (relative to the context path) of the SSO page
     */
    public SsoAuthenticationEntryPoint(final String ssoEntryPage) {
        this.ssoEntryPage = ssoEntryPage;
    }

    /**
     * Redirects the sender of a request which has failed authentication to the SSO page
     */
    @Override
    public void commence(final HttpServletRequest request, final HttpServletResponse response, final AuthenticationException authException) throws IOException, ServletException {
        response.sendRedirect(request.getContextPath() + ssoEntryPage);
    }
}
