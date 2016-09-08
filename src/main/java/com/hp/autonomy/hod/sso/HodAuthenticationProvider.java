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

import java.io.IOException;
import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.UUID;

/**
 * AuthenticationProvider which consumes {@link HodTokenAuthentication} and produces {@link HodAuthentication}
 */
public class HodAuthenticationProvider implements AuthenticationProvider {
    private final GrantedAuthoritiesResolver authoritiesResolver;
    private final TokenRepository tokenRepository;
    private final AuthenticationService authenticationService;
    private final UserStoreUsersService userStoreUsersService;
    private final HodUserMetadataResolver hodUserMetadataResolver;
    private final UnboundTokenService<TokenType.HmacSha1> unboundTokenService;
    private final SecurityInfoRetriever securityInfoRetriever;

    /**
     * Creates a new HodAuthenticationProvider which fetches the given user metadata keys. Note: this will only work if
     * the combined token has the privilege for the Get User Metadata API on their user store. Uses the given username
     * resolver to set the name for a user's {@link HodAuthenticationPrincipal}. The GrantedAuthoritiesResolver is used
     * to create a collection of authorities for an authenticated user.
     *
     * @param tokenRepository         The token repository in which to store the HP Haven OnDemand Token
     * @param authoritiesResolver     Resolves authorities for authenticated users
     * @param authenticationService   The authentication service that will perform the authentication
     * @param unboundTokenService     The unbound token service to get the unbound authentication UUID from
     * @param userStoreUsersService   The user store users service that will get user metadata
     * @param hodUserMetadataResolver The strategy to resolve users' metadata
     */
    public HodAuthenticationProvider(
            final TokenRepository tokenRepository,
            final GrantedAuthoritiesResolver authoritiesResolver,
            final AuthenticationService authenticationService,
            final UnboundTokenService<TokenType.HmacSha1> unboundTokenService,
            final UserStoreUsersService userStoreUsersService,
            final HodUserMetadataResolver hodUserMetadataResolver,
            final SecurityInfoRetriever securityInfoRetriever
    ) {
        this.tokenRepository = tokenRepository;
        this.authenticationService = authenticationService;
        this.userStoreUsersService = userStoreUsersService;
        this.hodUserMetadataResolver = hodUserMetadataResolver;
        this.unboundTokenService = unboundTokenService;
        this.authoritiesResolver = authoritiesResolver;
        this.securityInfoRetriever = securityInfoRetriever;
    }

    /**
     * Creates a new HodAuthenticationProvider which doesn't fetch user metadata. The GrantedAuthoritiesResolver is used
     * to create a collection of authorities for an authenticated user.
     * @param tokenRepository       The token repository in which to store the HP Haven OnDemand Token
     * @param authoritiesResolver   Resolves authorities for authenticated users
     * @param authenticationService The authentication service that will perform the authentication
     * @param unboundTokenService   The unbound token service to get the unbound authentication UUID from
     */
    public HodAuthenticationProvider(
            final TokenRepository tokenRepository,
            final GrantedAuthoritiesResolver authoritiesResolver,
            final AuthenticationService authenticationService,
            final UnboundTokenService<TokenType.HmacSha1> unboundTokenService
    ) {
        this(tokenRepository, authoritiesResolver, authenticationService, unboundTokenService, null, null, null);
    }

    /**
     * Creates a new HodAuthenticationProvider which fetches the given user metadata keys. Note: this will only work if
     * the combined token has the privilege for the Get User Metadata API on their user store. Uses the given username
     * resolver to set the name for a user's {@link HodAuthenticationPrincipal}. The role is given to every user as a
     * granted authority.
     *
     * @param tokenRepository         The token repository in which to store the HP Haven OnDemand Token
     * @param role                    The role to assign to users authenticated with HP Haven OnDemand SSO
     * @param authenticationService   The authentication service that will perform the authentication
     * @param unboundTokenService     The unbound token service to get the unbound authentication UUID from
     * @param userStoreUsersService   The user store users service that will get user metadata
     * @param hodUserMetadataResolver The strategy to resolve users' metadata
     */
    public HodAuthenticationProvider(
            final TokenRepository tokenRepository,
            final String role,
            final AuthenticationService authenticationService,
            final UnboundTokenService<TokenType.HmacSha1> unboundTokenService,
            final UserStoreUsersService userStoreUsersService,
            final HodUserMetadataResolver hodUserMetadataResolver
    ) {
        this(tokenRepository, new ConstantAuthoritiesResolver(role), authenticationService, unboundTokenService, userStoreUsersService, hodUserMetadataResolver, null);
    }

    public HodAuthenticationProvider(
            final TokenRepository tokenRepository,
            final String role,
            final AuthenticationService authenticationService,
            final UnboundTokenService<TokenType.HmacSha1> unboundTokenService,
            final UserStoreUsersService userStoreUsersService,
            final HodUserMetadataResolver hodUserMetadataResolver,
            final SecurityInfoRetriever securityInfoRetriever
    ) {
        this(tokenRepository, new ConstantAuthoritiesResolver(role), authenticationService, unboundTokenService, userStoreUsersService, hodUserMetadataResolver, securityInfoRetriever);
    }

    /**
     * Creates a new HodAuthenticationProvider which fetches the given user metadata keys. Note: this will only work if
     * the combined token has the privilege for the Get User Metadata API on their user store. The role is given to every
     * user as a granted authority.
     *
     * @param tokenRepository       The token repository in which to store the HP Haven OnDemand Token
     * @param role                  The role to assign to users authenticated with HP Haven OnDemand SSO
     * @param authenticationService The authentication service that will perform the authentication
     * @param unboundTokenService   The unbound token service to get the unbound authentication UUID from
     * @param userStoreUsersService The user store users service that will get user metadata
     */
    public HodAuthenticationProvider(
            final TokenRepository tokenRepository,
            final String role,
            final AuthenticationService authenticationService,
            final UnboundTokenService<TokenType.HmacSha1> unboundTokenService,
            final UserStoreUsersService userStoreUsersService
    ) {
        this(tokenRepository, role, authenticationService, unboundTokenService, userStoreUsersService, null, null);
    }

    /**
     * Creates a new HodAuthenticationProvider which doesn't fetch user metadata. The role is given to every user as a
     * granted authority.
     *
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
    ) {
        this(tokenRepository, role, authenticationService, unboundTokenService, null, null, null);
    }

    /**
     * Authenticates the given authentication
     *
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

        final UUID unboundAuthenticationUuid;

        try {
            unboundAuthenticationUuid = unboundTokenService.getAuthenticationUuid();
        } catch (final HodErrorException e) {
            throw new AuthenticationServiceException("HOD returned an error while authenticating", e);
        }

        if (!unboundAuthenticationUuid.equals(combinedTokenInformation.getApplication().getAuthentication().getUuid())) {
            // The provided combined token was not generated with our unbound token
            throw new BadCredentialsException("Invalid combined token");
        }

        final TokenProxy<EntityType.Combined, TokenType.Simple> combinedTokenProxy;

        try {
            combinedTokenProxy = tokenRepository.insert(combinedToken);
        } catch (final IOException e) {
            throw new AuthenticationServiceException("An error occurred while authenticating", e);
        }

        final HodUserMetadata metadata;

        final ResourceIdentifier userStore = combinedTokenInformation.getUserStore().getIdentifier();

        try {
            metadata = retrieveMetadata(combinedTokenProxy, combinedTokenInformation, userStore);
        } catch (final HodErrorException e) {
            throw new AuthenticationServiceException("Hod returned an error while authenticating", e);
        }

        String securityInfo = null;

        if (securityInfoRetriever != null) {
            try {
                securityInfo = securityInfoRetriever.getSecurityInfo(combinedTokenInformation.getUser());
            } catch (final Exception e) {
                throw new AuthenticationServiceException("There was an error while authenticating", e);
            }
            if (securityInfo == null) {
                throw new AuthenticationServiceException("There was an error while authenticating");
            }
        }

        final HodAuthenticationPrincipal principal = new HodAuthenticationPrincipal(combinedTokenInformation, metadata.getUserDisplayName(), metadata.getMetadata(), securityInfo);
        final ResourceIdentifier applicationIdentifier = combinedTokenInformation.getApplication().getIdentifier();

        // Resolve application granted authorities, adding an authority representing the HOD application
        final Collection<GrantedAuthority> grantedAuthorities = ImmutableSet.<GrantedAuthority>builder()
                .addAll(authoritiesResolver.resolveAuthorities(combinedTokenProxy, combinedTokenInformation))
                .add(new HodApplicationGrantedAuthority(applicationIdentifier))
                .build();

        return new HodAuthentication<>(combinedTokenProxy, grantedAuthorities, principal);
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

    private HodUserMetadata retrieveMetadata (
            final TokenProxy<EntityType.Combined, TokenType.Simple> combinedTokenProxy,
            final CombinedTokenInformation combinedTokenInformation,
            final ResourceIdentifier userStore
    ) throws HodErrorException {
        return userStoreUsersService == null ?
                new HodUserMetadata("", Collections.<String, Serializable>emptyMap()) :
                hodUserMetadataResolver.resolve(userStoreUsersService.getUserMetadata(combinedTokenProxy, userStore, combinedTokenInformation.getUser().getUuid()));
    }
}
