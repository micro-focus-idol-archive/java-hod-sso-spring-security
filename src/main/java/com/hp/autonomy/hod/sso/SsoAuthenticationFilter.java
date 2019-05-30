/*
 * Copyright 2015-2018 Micro Focus International plc.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * An authentication processing filter which parses a combined SSO token from a POST body.
 */
public class SsoAuthenticationFilter<E extends EntityType> extends AbstractAuthenticationProcessingFilter {
    private final E entityType;

    public SsoAuthenticationFilter(final String authenticationPath, final E entityType) {
        super(new AntPathRequestMatcher(authenticationPath, "POST"));
        this.entityType = entityType;
    }

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if (!StringUtils.isEmpty(request.getParameter("error"))) {
            throw new AuthenticationServiceException("The SSO page returned an error");
        }

        final DateTime expiry;

        try {
            expiry = new DateTime(Long.parseLong(request.getParameter("expiry")));
        } catch (final NumberFormatException ignored) {
            throw new BadCredentialsException("Invalid combined SSO token");
        }

        final AuthenticationToken<E, TokenType.Simple> token = new AuthenticationToken<>(
            entityType,
            TokenType.Simple.INSTANCE,
            request.getParameter("type"),
            expiry,
            request.getParameter("id"),
            request.getParameter("secret"),
            null
        );

        return getAuthenticationManager().authenticate(new HodTokenAuthentication<>(token));
    }
}
