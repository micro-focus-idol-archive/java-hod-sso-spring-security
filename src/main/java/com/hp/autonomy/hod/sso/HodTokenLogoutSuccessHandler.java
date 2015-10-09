/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.token.TokenRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * A {@link LogoutSuccessHandler} which gets the combined token from the given HodAuthentication then redirects the
 * browser to the given redirect path, appending the token in a query parameter. This allows client side JS to log the
 * user out of HOD SSO after the Spring session has been destroyed.
 * The Spring {@link org.springframework.security.core.context.SecurityContextHolder} must contain a {@link HodAuthentication}
 * when {@link #onLogoutSuccess(HttpServletRequest, HttpServletResponse, Authentication)} is called.
 */
public class HodTokenLogoutSuccessHandler implements LogoutSuccessHandler {
    private final String redirectPath;
    private final TokenRepository tokenRepository;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * Construct a new HodTokenLogoutSuccessHandler using the given redirect path and token repository.
     * @param redirectPath Base path to use for the redirect
     * @param tokenRepository Used to convert the combined token proxy from the authentication into a combined token
     */
    public HodTokenLogoutSuccessHandler(final String redirectPath, final TokenRepository tokenRepository) {
        this.redirectPath = redirectPath;
        this.tokenRepository = tokenRepository;
    }

    @Override
    public void onLogoutSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException, ServletException {
        final HodAuthentication hodAuthentication = (HodAuthentication) authentication;
        final AuthenticationToken<EntityType.Combined, TokenType.Simple> combinedToken = tokenRepository.get(hodAuthentication.getTokenProxy());
        redirectStrategy.sendRedirect(request, response, redirectPath + "?token=" + uriEncode(combinedToken.toString()));
    }

    private String uriEncode(final String input) {
        try {
            return URLEncoder.encode(input, StandardCharsets.UTF_8.name());
        } catch (final UnsupportedEncodingException e) {
            throw new RuntimeException("This should never happen", e);
        }
    }
}
