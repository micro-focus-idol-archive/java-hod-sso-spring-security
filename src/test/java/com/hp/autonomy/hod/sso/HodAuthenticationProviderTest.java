/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.hp.autonomy.hod.client.api.authentication.ApplicationAndUsers;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationService;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationType;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.ApplicationInformation;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.AuthenticationInformation;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.CombinedTokenInformation;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.GroupInformation;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.GroupUserStoreInformation;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.UserInformation;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.UserStoreInformation;
import com.hp.autonomy.hod.client.api.resource.ResourceIdentifier;
import com.hp.autonomy.hod.client.api.userstore.user.Account;
import com.hp.autonomy.hod.client.api.userstore.user.UserStoreUsersService;
import com.hp.autonomy.hod.client.error.HodError;
import com.hp.autonomy.hod.client.error.HodErrorCode;
import com.hp.autonomy.hod.client.error.HodErrorException;
import com.hp.autonomy.hod.client.token.TokenProxy;
import com.hp.autonomy.hod.client.token.TokenRepository;
import org.joda.time.DateTime;
import org.joda.time.Hours;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class HodAuthenticationProviderTest {
    private static final String APPLICATION_NAME = "application_name";
    private static final String APPLICATION_DOMAIN = "application_domain";
    private static final String USERSTORE_NAME = "userstore_name";
    private static final String USERSTORE_DOMAIN = "userstore_domain";
    private static final UUID USER_UUID = UUID.randomUUID();
    private static final String USER_ROLE = "ROLE_USER";

    @Mock
    private UserStoreUsersService userStoreUsersService;

    @Mock
    private AuthenticationService authenticationService;

    @Mock
    private UnboundTokenService<TokenType.HmacSha1> unboundTokenService;

    @Mock
    private TokenRepository tokenRepository;

    private AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken;
    private AuthenticationToken<EntityType.CombinedSso, TokenType.Simple> combinedSsoToken;
    private AuthenticationToken<EntityType.Combined, TokenType.Simple> combinedToken;
    private TokenProxy<EntityType.Combined, TokenType.Simple> tokenProxy;

    @Before
    public void initialise() throws IOException, HodErrorException {
        tokenProxy = new TokenProxy<>(EntityType.Combined.INSTANCE, TokenType.Simple.INSTANCE);

        combinedToken = mockToken(EntityType.Combined.INSTANCE, TokenType.Simple.INSTANCE);
        unboundToken = mockToken(EntityType.Unbound.INSTANCE, TokenType.HmacSha1.INSTANCE);
        combinedSsoToken = mockToken(EntityType.CombinedSso.INSTANCE, TokenType.Simple.INSTANCE);

        when(unboundTokenService.getUnboundToken()).thenReturn(unboundToken);
        when(authenticationService.authenticateCombinedGet(combinedSsoToken, unboundToken)).thenReturn(mockApplicationAndUsersList(TokenType.Simple.INSTANCE));

        when(authenticationService.authenticateCombined(
                combinedSsoToken,
                unboundToken,
                APPLICATION_DOMAIN,
                APPLICATION_NAME,
                USERSTORE_DOMAIN,
                USERSTORE_NAME,
                TokenType.Simple.INSTANCE
        )).thenReturn(combinedToken);

        when(authenticationService.getCombinedTokenInformation(combinedToken)).thenReturn(mockCombinedTokenInformation());

        when(tokenRepository.insert(combinedToken)).thenReturn(tokenProxy);
    }

    @Test
    public void supportsHodTokenAuthentication() {
        final HodAuthenticationProvider provider = createSimpleProvider();
        assertThat(provider.supports(HodTokenAuthentication.class), is(true));
    }

    @Test
    public void doesNotSupportGeneralAuthentication() {
        final HodAuthenticationProvider provider = createSimpleProvider();
        assertThat(provider.supports(Authentication.class), is(false));
    }

    @Test(expected = AuthenticationServiceException.class)
    public void handlesHodErrorExceptionFromUnboundTokenService() throws HodErrorException {
        when(unboundTokenService.getUnboundToken()).thenThrow(mockAuthenticationFailedException());

        createSimpleProvider().authenticate(new HodTokenAuthentication(combinedSsoToken));
    }

    @Test(expected = BadCredentialsException.class)
    public void failsAuthenticationIfCombinedSsoTokenInvalid() throws HodErrorException {
        when(authenticationService.authenticateCombinedGet(combinedSsoToken, unboundToken)).thenThrow(mockAuthenticationFailedException());

        createSimpleProvider().authenticate(new HodTokenAuthentication(combinedSsoToken));
    }

    @Test(expected = AuthenticationServiceException.class)
    public void handlesHodErrorOnAuthenticateCombinedGet() throws HodErrorException {
        when(authenticationService.authenticateCombinedGet(combinedSsoToken, unboundToken)).thenThrow(mockFatalDatabaseException());

        createSimpleProvider().authenticate(new HodTokenAuthentication(combinedSsoToken));
    }

    @Test(expected = BadCredentialsException.class)
    public void failsAuthenticationIfNoApplications() throws HodErrorException {
        when(authenticationService.authenticateCombinedGet(combinedSsoToken, unboundToken)).thenReturn(Collections.<ApplicationAndUsers>emptyList());

        createSimpleProvider().authenticate(new HodTokenAuthentication(combinedSsoToken));
    }

    @Test(expected = AuthenticationServiceException.class)
    public void failsAuthenticationIfSimpleTokenTypeNotAllowed() throws HodErrorException {
        when(authenticationService.authenticateCombinedGet(combinedSsoToken, unboundToken)).thenReturn(mockApplicationAndUsersList(TokenType.HmacSha1.INSTANCE));

        createSimpleProvider().authenticate(new HodTokenAuthentication(combinedSsoToken));
    }

    @Test(expected = AuthenticationServiceException.class)
    public void handlesHodExceptionFromAuthenticateCombined() throws HodErrorException {
        when(authenticationService.authenticateCombined(
                combinedSsoToken,
                unboundToken,
                APPLICATION_DOMAIN,
                APPLICATION_NAME,
                USERSTORE_DOMAIN,
                USERSTORE_NAME,
                TokenType.Simple.INSTANCE
        )).thenThrow(mockFatalDatabaseException());

        createSimpleProvider().authenticate(new HodTokenAuthentication(combinedSsoToken));
    }

    @Test(expected = AuthenticationServiceException.class)
    public void handlesHodErrorExceptionFromCombinedTokenInformation() throws HodErrorException {
        when(authenticationService.getCombinedTokenInformation(combinedToken)).thenThrow(mockFatalDatabaseException());

        createSimpleProvider().authenticate(new HodTokenAuthentication(combinedSsoToken));
    }

    @Test(expected = AuthenticationServiceException.class)
    public void handlesIOExceptionFromTokenRepository() throws IOException {
        when(tokenRepository.insert(combinedToken)).thenThrow(mock(IOException.class));

        createSimpleProvider().authenticate(new HodTokenAuthentication(combinedSsoToken));
    }


    @Test
    public void authenticatesWithRole() throws HodErrorException, IOException {
        final HodAuthenticationProvider provider = createSimpleProvider();
        final Authentication tokenAuthentication = new HodTokenAuthentication(combinedSsoToken);

        @SuppressWarnings("unchecked")
        final HodAuthentication<EntityType.Combined> authentication = (HodAuthentication<EntityType.Combined>) provider.authenticate(tokenAuthentication);

        verify(tokenRepository, times(1)).insert(combinedToken);

        assertThat(authentication.getTokenProxy(), is(tokenProxy));

        final HodAuthenticationPrincipal principal = authentication.getPrincipal();

        assertThat(principal.getApplication().getName(), is(APPLICATION_NAME));
        assertThat(principal.getUserUuid(), is(USER_UUID));
        assertThat(principal.getUserMetadata().size(), is(0));

        final Collection<GrantedAuthority> authorities = authentication.getAuthorities();

        assertThat(authorities, containsInAnyOrder(
                new SimpleGrantedAuthority(USER_ROLE),
                new HodApplicationGrantedAuthority(new ResourceIdentifier(APPLICATION_DOMAIN, APPLICATION_NAME))
        ));
    }

    @Test
    public void authenticatesWithAuthoritiesResolver() throws HodErrorException {
        final GrantedAuthoritiesResolver resolver = new GrantedAuthoritiesResolver() {
            @Override
            public Collection<GrantedAuthority> resolveAuthorities(final TokenProxy<EntityType.Combined, TokenType.Simple> tokenProxy, final CombinedTokenInformation combinedTokenInformation) {
                return ImmutableList.<GrantedAuthority>builder()
                        .add(new SimpleGrantedAuthority("ROLE_1"))
                        .add(new SimpleGrantedAuthority("ROLE_2"))
                        .build();
            }
        };

        final AuthenticationProvider provider = new HodAuthenticationProvider(tokenRepository, resolver, authenticationService, unboundTokenService);
        final Authentication authentication = provider.authenticate(new HodTokenAuthentication(combinedSsoToken));

        assertThat(authentication.getAuthorities(), containsInAnyOrder(
                new SimpleGrantedAuthority("ROLE_1"),
                new SimpleGrantedAuthority("ROLE_2"),
                new HodApplicationGrantedAuthority(new ResourceIdentifier(APPLICATION_DOMAIN, APPLICATION_NAME))
        ));
    }

    @Test
    public void authenticatesWithUsernameResolver() throws HodErrorException {
        final Map<String, JsonNode> hodMetadata = ImmutableMap.<String, JsonNode>builder()
                .put("username", mock(JsonNode.class))
                .put("manager", mock(JsonNode.class))
                .build();
        final Map<String, Serializable> outputMetadata = ImmutableMap.<String, Serializable>builder()
                .put("username", "fred")
                .put("manager", "penny")
                .build();

        final AuthenticationProvider provider = new HodAuthenticationProvider(
                tokenRepository,
                USER_ROLE,
                authenticationService,
                unboundTokenService,
                userStoreUsersService,
                new HodUserMetadataResolver() {
                    @Override
                    public HodUserMetadata resolve(final Map<String, JsonNode> metadata) {
                        return new HodUserMetadata("fred", outputMetadata);
                    }
                }
        );

        when(userStoreUsersService.getUserMetadata(tokenProxy, new ResourceIdentifier(USERSTORE_DOMAIN, USERSTORE_NAME), USER_UUID))
                .thenReturn(hodMetadata);

        final Authentication authentication = provider.authenticate(new HodTokenAuthentication(combinedSsoToken));
        assertThat(authentication.getName(), is("fred"));
    }

    private HodAuthenticationProvider createSimpleProvider() {
        return new HodAuthenticationProvider(tokenRepository, USER_ROLE, authenticationService, unboundTokenService);
    }

    private CombinedTokenInformation mockCombinedTokenInformation() {
        final AuthenticationInformation applicationAuthenticationInformation = new AuthenticationInformation(UUID.randomUUID(), AuthenticationType.LEGACY_API_KEY);
        final AuthenticationInformation userAuthenticationInformation = new AuthenticationInformation(UUID.randomUUID(), AuthenticationType.LEGACY_API_KEY);

        final ApplicationInformation applicationInformation = new ApplicationInformation(APPLICATION_NAME, APPLICATION_DOMAIN, applicationAuthenticationInformation);
        final UserStoreInformation userStoreInformation = new UserStoreInformation(UUID.randomUUID(), USERSTORE_NAME, USERSTORE_DOMAIN);
        final Account account = new Account(Account.Type.EMAIL, "meg.whitman@hpe.com", Account.Status.CONFIRMED, true);
        final GroupUserStoreInformation groupUserStoreInformation = new GroupUserStoreInformation(USERSTORE_NAME, USERSTORE_DOMAIN, USERSTORE_DOMAIN + ':' + USERSTORE_NAME);
        final GroupInformation groupInformation = new GroupInformation(groupUserStoreInformation, Collections.singleton("ceo"));
        final UserInformation userInformation = new UserInformation(USER_UUID, userAuthenticationInformation, Collections.singletonList(account), Collections.singletonList(groupInformation));

        return new CombinedTokenInformation(UUID.randomUUID(), applicationInformation, userStoreInformation, userInformation);
    }

    private <E extends EntityType, T extends TokenType> AuthenticationToken<E, T> mockToken(final E entityType, final T tokenType) {
        return new AuthenticationToken<>(
                entityType,
                tokenType,
                DateTime.now().plus(Hours.TWO),
                "token-id-" + UUID.randomUUID().toString(),
                "token-secret-" + UUID.randomUUID().toString(),
                DateTime.now().plus(Hours.ONE)
        );
    }

    private List<ApplicationAndUsers> mockApplicationAndUsersList(final TokenType supportedTokenType) {
        final List<ApplicationAndUsers.User> users = Arrays.asList(
                new ApplicationAndUsers.User(USERSTORE_NAME, USERSTORE_DOMAIN, null),
                new ApplicationAndUsers.User("Wrong Userstore 1", "Wrong Userstore Domain 1", null)
        );

        final ApplicationAndUsers.User wrongUser = new ApplicationAndUsers.User("Wrong Userstore 2", "Wrong Userstore Domain 2", null);

        return Arrays.asList(
                new ApplicationAndUsers(APPLICATION_NAME, APPLICATION_DOMAIN, null, null, Collections.singletonList(supportedTokenType.getName()), users),
                new ApplicationAndUsers("Wrong App", "Wrong Domain", null, null, Collections.singletonList(TokenType.Simple.INSTANCE.getName()), Collections.singletonList(wrongUser))
        );
    }

    private HodErrorException mockFatalDatabaseException() {
        final HodError hodError = new HodError.Builder()
                .setErrorCode(HodErrorCode.FATAL_DATABASE_ERROR)
                .setDetail("Fatal database error")
                .build();

        return new HodErrorException(hodError, 500);
    }

    private HodErrorException mockAuthenticationFailedException() {
        final HodError hodError = new HodError.Builder()
                .setErrorCode(HodErrorCode.AUTHENTICATION_FAILED)
                .setDetail("Authentication failed")
                .build();

        return new HodErrorException(hodError, 401);
    }
}