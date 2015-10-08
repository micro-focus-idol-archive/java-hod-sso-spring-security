/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.google.common.collect.ImmutableSet;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationService;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.CombinedTokenInformation;
import com.hp.autonomy.hod.client.api.resource.ResourceIdentifier;
import com.hp.autonomy.hod.client.error.HodErrorCode;
import com.hp.autonomy.hod.client.error.HodErrorException;
import com.hp.autonomy.hod.client.token.TokenProxy;
import com.hp.autonomy.hod.client.token.TokenRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.Collection;

/**
 * AuthenticationProvider which consumes {@link HodTokenAuthentication} and produces {@link HodAuthentication}
 */
public class HodAuthenticationProvider implements AuthenticationProvider {
    private final String role;
    private final TokenRepository tokenRepository;
    private final AuthenticationService authenticationService;

    /**
     * Creates a new HodAuthenticationProvider
     * @param tokenRepository The token repository in which to store the HP Haven OnDemand Token
     * @param role The role to assign to users authenticated with HP Haven OnDemand SSO
     * @param authenticationService The authentication service that will perform the authentication
     */
    public HodAuthenticationProvider(final TokenRepository tokenRepository, final String role, final AuthenticationService authenticationService) {
        this.role = role;
        this.tokenRepository = tokenRepository;
        this.authenticationService = authenticationService;
    }

    /**
     * Authenticates the given authentication
     * @param authentication The authentication to authenticate. This should be a HodTokenAuthentication
     * @return A HodAuthentication based on the given HodTokenAuthentication
     * @throws AuthenticationException if authentication fails
     */
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final AuthenticationToken<EntityType.Combined, TokenType.Simple> combinedToken = ((HodTokenAuthentication) authentication).getCredentials();
        final CombinedTokenInformation combinedTokenInformation;

        try {
            combinedTokenInformation = authenticationService.getCombinedTokenInformation(combinedToken);
        } catch (final HodErrorException e) {
            if (HodErrorCode.AUTHENTICATION_FAILED.equals(e.getErrorCode())) {
                throw new BadCredentialsException("HOD authentication failed", e);
            } else {
                throw new AuthenticationServiceException("HOD returned an error while authenticating", e);
            }
        }

        // TODO: Verify the combined token once IOD-6246 is complete (CCUK-3314)

        final TokenProxy<EntityType.Combined, TokenType.Simple> combinedTokenProxy;

        try {
            combinedTokenProxy = tokenRepository.insert(combinedToken);
        } catch (final IOException e) {
            throw new AuthenticationServiceException("An error occurred while authenticating", e);
        }

        final ResourceIdentifier applicationIdentifier = combinedTokenInformation.getApplication().getIdentifier();

        // Give user access to load the application (via the role) and permission to access resources associated with the HOD application
        final Collection<GrantedAuthority> grantedAuthorities = ImmutableSet.<GrantedAuthority>builder()
                .add(new SimpleGrantedAuthority(role))
                .add(new HodApplicationGrantedAuthority(applicationIdentifier))
                .build();

        return new HodAuthentication(
            combinedTokenProxy,
            grantedAuthorities,
            combinedTokenInformation.getUser().getName(),
            applicationIdentifier.getDomain(),
            applicationIdentifier.getName()
        );
    }

    /**
     * Test if the authentication provider supports a particular authentication class
     * @param authenticationClass The class to test
     * @return True is the class is assignable from HodTokenAuthentication; false otherwise
     */
    @Override
    public boolean supports(final Class<?> authenticationClass) {
        return HodTokenAuthentication.class.isAssignableFrom(authenticationClass);
    }
}
