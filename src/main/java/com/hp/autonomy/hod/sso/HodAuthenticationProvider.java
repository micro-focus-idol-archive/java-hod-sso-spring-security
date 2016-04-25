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
import com.hp.autonomy.hod.client.api.userstore.user.UserStoreUsersService;
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
import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * AuthenticationProvider which consumes {@link HodTokenAuthentication} and produces {@link HodAuthentication}
 */
public class HodAuthenticationProvider implements AuthenticationProvider {
    private final String role;
    private final TokenRepository tokenRepository;
    private final AuthenticationService authenticationService;
    private final UserStoreUsersService userStoreUsersService;
    private final AtomicReference<UUID> unboundAuthenticationUuid = new AtomicReference<>();
    private final Map<String, Class<? extends Serializable>> metadataTypes;
    private final HodUsernameResolver hodUsernameResolver;
    private final UnboundTokenService<TokenType.HmacSha1> unboundTokenService;

    /**
     * Creates a new HodAuthenticationProvider which fetches the given user metadata keys. Note: this will only work if
     * the combined token has the privilege for the Get User Metadata API on their user store. Uses the given username
     * resolver to set the name for a user's {@link HodAuthenticationPrincipal}.
     * @param tokenRepository       The token repository in which to store the HP Haven OnDemand Token
     * @param role                  The role to assign to users authenticated with HP Haven OnDemand SSO
     * @param authenticationService The authentication service that will perform the authentication
     * @param unboundTokenService   The unbound token service to get the unbound authentication UUID from
     * @param userStoreUsersService The user store users service that will get user metadata
     * @param metadataTypes         Metadata keys and types to retrieve and incorporate into the HodAuthentication principal
     * @param hodUsernameResolver   The strategy to extract usernames from users' metadata
     */
    public HodAuthenticationProvider(
            final TokenRepository tokenRepository,
            final String role,
            final AuthenticationService authenticationService,
            final UnboundTokenService<TokenType.HmacSha1> unboundTokenService,
            final UserStoreUsersService userStoreUsersService,
            final Map<String, Class<? extends Serializable>> metadataTypes,
            final HodUsernameResolver hodUsernameResolver
    ) throws HodErrorException {
        this.role = role;
        this.tokenRepository = tokenRepository;
        this.authenticationService = authenticationService;
        this.userStoreUsersService = userStoreUsersService;
        this.metadataTypes = metadataTypes;
        this.hodUsernameResolver = hodUsernameResolver;
        this.unboundTokenService = unboundTokenService;
    }

    /**
     * Creates a new HodAuthenticationProvider which fetches the given user metadata keys. Note: this will only work if
     * the combined token has the privilege for the Get User Metadata API on their user store.
     * @param tokenRepository       The token repository in which to store the HP Haven OnDemand Token
     * @param role                  The role to assign to users authenticated with HP Haven OnDemand SSO
     * @param authenticationService The authentication service that will perform the authentication
     * @param unboundTokenService   The unbound token service to get the unbound authentication UUID from
     * @param userStoreUsersService The user store users service that will get user metadata
     * @param metadataTypes         Metadata keys and types to retrieve and incorporate into the HodAuthentication principal
     */
    public HodAuthenticationProvider(
            final TokenRepository tokenRepository,
            final String role,
            final AuthenticationService authenticationService,
            final UnboundTokenService<TokenType.HmacSha1> unboundTokenService,
            final UserStoreUsersService userStoreUsersService,
            final Map<String, Class<? extends Serializable>> metadataTypes
    ) throws HodErrorException {
        this(tokenRepository, role, authenticationService, unboundTokenService, userStoreUsersService, metadataTypes, null);
    }

    /**
     * Creates a new HodAuthenticationProvider which doesn't fetch user metadata.
     * @param tokenRepository       The token repository in which to store the HP Haven OnDemand Token
     * @param role                  The role to assign to users authenticated with HP Haven OnDemand SSO
     * @param authenticationService The authentication service that will perform the authentication
     * @param unboundTokenService   The unbound token service to get the unbound authentication UUID from
     */
    public HodAuthenticationProvider(
            final TokenRepository tokenRepository,
            final String role,
            final AuthenticationService authenticationService,
            final UnboundTokenService<TokenType.HmacSha1> unboundTokenService
    ) throws HodErrorException {
        this(tokenRepository, role, authenticationService, unboundTokenService, null, null, null);
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

        if (unboundAuthenticationUuid.get() == null) {
            try {
                unboundAuthenticationUuid.set(unboundTokenService.getAuthenticationUuid());
            } catch (final HodErrorException e) {
                throw new AuthenticationServiceException("HOD returned an error while authenticating", e);
            }
        }

        if (!unboundAuthenticationUuid.get().equals(combinedTokenInformation.getApplication().getAuthentication().getUuid())) {
            // The provided combined token was not generated with our unbound token
            throw new BadCredentialsException("Invalid combined token");
        }

        final TokenProxy<EntityType.Combined, TokenType.Simple> combinedTokenProxy;

        try {
            combinedTokenProxy = tokenRepository.insert(combinedToken);
        } catch (final IOException e) {
            throw new AuthenticationServiceException("An error occurred while authenticating", e);
        }

        Map<String, Serializable> metadata = new HashMap<>();
        String name = null;

        if (metadataTypes != null) {
            try {
                metadata = userStoreUsersService.getUserMetadata(
                        combinedTokenProxy,
                        combinedTokenInformation.getUserStore().getIdentifier(),
                        combinedTokenInformation.getUser().getUuid(),
                        metadataTypes
                );

                if (hodUsernameResolver != null) {
                    name = hodUsernameResolver.resolve(metadata);
                }
            } catch (final HodErrorException e) {
                throw new AuthenticationServiceException("HOD returned an error while authenticating", e);
            }
        }

        final HodAuthenticationPrincipal principal = new HodAuthenticationPrincipal(combinedTokenInformation, name, metadata);
        final ResourceIdentifier applicationIdentifier = combinedTokenInformation.getApplication().getIdentifier();

        // Give user access to load the application (via the role) and permission to access resources associated with the HOD application
        final Collection<GrantedAuthority> grantedAuthorities = ImmutableSet.<GrantedAuthority>builder()
                .add(new SimpleGrantedAuthority(role))
                .add(new HodApplicationGrantedAuthority(applicationIdentifier))
                .build();

        return new HodAuthentication<>(
                combinedTokenProxy,
                grantedAuthorities,
                principal
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
