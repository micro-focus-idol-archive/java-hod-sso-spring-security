/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SsoAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    public SsoAuthenticationFilter(final String authenticationPath) {
        super(new AntPathRequestMatcher(authenticationPath, "POST"));
    }

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        final long expiry;
        final long startRefresh;

        try {
            expiry = Long.parseLong(request.getParameter("expiry"));
            startRefresh = Long.parseLong(request.getParameter("startRefresh"));
        } catch (final NumberFormatException e) {
            throw new BadCredentialsException("Invalid user unbound token");
        }

        final AuthenticationToken token = new AuthenticationToken(
                expiry,
                request.getParameter("id"),
                request.getParameter("secret"),
                request.getParameter("type"),
                startRefresh
        );

        return getAuthenticationManager().authenticate(new HodTokenAuthentication(token));
    }
}
