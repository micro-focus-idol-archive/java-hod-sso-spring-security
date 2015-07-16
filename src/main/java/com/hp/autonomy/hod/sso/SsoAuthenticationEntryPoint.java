/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SsoAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final String ssoEntryPage;

    public SsoAuthenticationEntryPoint(final String ssoEntryPage) {
        this.ssoEntryPage = ssoEntryPage;
    }

    @Override
    public void commence(final HttpServletRequest request, final HttpServletResponse response, final AuthenticationException authException) throws IOException, ServletException {
        response.sendRedirect(request.getContextPath() + ssoEntryPage);
    }
}
