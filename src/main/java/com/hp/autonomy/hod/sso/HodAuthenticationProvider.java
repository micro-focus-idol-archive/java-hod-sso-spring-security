/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.google.common.collect.ImmutableSet;
import com.hp.autonomy.hod.client.api.authentication.ApplicationAndUsers;
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
import java.util.List;

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
     *
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
        final AuthenticationToken<EntityType.CombinedSso, TokenType.Simple> combinedSsoToken = ((HodTokenAuthentication) authentication).getCredentials();
        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken;

        try {
            // Get an unbound token for the application's authentication
            unboundToken = unboundTokenService.getUnboundToken();
        } catch (final HodErrorException e) {
            // If an authentication error occurs here, it is the application's fault so don't throw BadCredentialsException
            throw new AuthenticationServiceException("HOD returned an error while authenticating", e);
        }

        final List<ApplicationAndUsers> applicationAndUsersList;

        try {
            // Determine what applications and users can be authenticated with the combined SSO and unbound tokens
            applicationAndUsersList = authenticationService.authenticateCombinedGet(combinedSsoToken, unboundToken);
        } catch (final HodErrorException e) {
            if (HodErrorCode.AUTHENTICATION_FAILED == e.getErrorCode()) {
                // The user's combined SSO token was invalid (we can assume our app token is valid)
                throw new BadCredentialsException("HOD authentication failed", e);
            } else {
                throw new AuthenticationServiceException("HOD returned an error while authenticating", e);
            }
        }

        if (applicationAndUsersList.isEmpty()) {
            // There are no application/user pairs matching the application and user authentication
            throw new BadCredentialsException("HOD authentication failed");
        }

        // TODO: Allow the user to choose which application/user pair to log in as
        // Choose the first application and user
        final ApplicationAndUsers applicationAndUsers = applicationAndUsersList.get(0);
        final ApplicationAndUsers.User user = applicationAndUsers.getUsers().get(0);

        if (!applicationAndUsers.getSupportedTokenTypes().contains(TokenType.Simple.INSTANCE.getName())) {
            // The HodAuthenticationProvider will try to create a simple token
            throw new AuthenticationServiceException("Simple token type not supported by application");
        }

        final ResourceIdentifier applicationIdentifier = new ResourceIdentifier(applicationAndUsers.getDomain(), applicationAndUsers.getName());
        final ResourceIdentifier userStore = new ResourceIdentifier(user.getDomain(), user.getUserStore());

        try {
            // Create a combined token
            final AuthenticationToken<EntityType.Combined, TokenType.Simple> combinedToken = authenticationService.authenticateCombined(
                    combinedSsoToken,
                    unboundToken,
                    applicationIdentifier.getDomain(),
                    applicationIdentifier.getName(),
                    userStore.getDomain(),
                    userStore.getName(),
                    TokenType.Simple.INSTANCE
            );

            final CombinedTokenInformation combinedTokenInformation = authenticationService.getCombinedTokenInformation(combinedToken);
            final String securityInfo = retrieveSecurityInfo(combinedTokenInformation);
            final TokenProxy<EntityType.Combined, TokenType.Simple> combinedTokenProxy = tokenRepository.insert(combinedToken);

            final HodUserMetadata metadata = retrieveMetadata(combinedTokenProxy, combinedTokenInformation, userStore);

            final HodAuthenticationPrincipal principal = new HodAuthenticationPrincipal(combinedTokenInformation, metadata.getUserDisplayName(), metadata.getMetadata(), securityInfo);

            // Resolve application granted authorities, adding an authority representing the HOD application
            final Collection<GrantedAuthority> grantedAuthorities = ImmutableSet.<GrantedAuthority>builder()
                    .addAll(authoritiesResolver.resolveAuthorities(combinedTokenProxy, combinedTokenInformation))
                    .add(new HodApplicationGrantedAuthority(applicationIdentifier))
                    .build();

            return new HodAuthentication<>(combinedTokenProxy, grantedAuthorities, principal);
        } catch (final HodErrorException e) {
            // The user's token has already been validated, so something else went wrong
            throw new AuthenticationServiceException("HOD returned an error while authenticating", e);
        } catch (final IOException e) {
            throw new AuthenticationServiceException("An error occurred while authenticating", e);
        }
    }

    /**
     * Test if the authentication provider supports a particular authentication class
     *
     * @param authenticationClass The class to test
     * @return True is the class is assignable from HodTokenAuthentication; false otherwise
     */
    @Override
    public boolean supports(final Class<?> authenticationClass) {
        return HodTokenAuthentication.class.isAssignableFrom(authenticationClass);
    }

    private String retrieveSecurityInfo(final CombinedTokenInformation combinedTokenInformation) {
        final String securityInfo;

        if (securityInfoRetriever == null) {
            securityInfo = null;
        } else {
            try {
                securityInfo = securityInfoRetriever.getSecurityInfo(combinedTokenInformation.getUser());
            } catch (final RuntimeException e) {
                throw new AuthenticationServiceException("Could not retrieve security info", e);
            }

            if (null == securityInfo) {
                throw new AuthenticationServiceException("Could not retrieve security info");
            }
        }

        return securityInfo;
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
