package com.hp.autonomy.hod.sso;

import com.google.common.collect.ImmutableList;
import com.hp.autonomy.hod.client.api.authentication.*;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.*;
import com.hp.autonomy.hod.client.api.resource.Resource;
import com.hp.autonomy.hod.client.api.resource.ResourceName;
import com.hp.autonomy.hod.client.api.userstore.user.Account;
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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.UUID;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

@SuppressWarnings("deprecation")
@RunWith(MockitoJUnitRunner.class)
public class CookieHodAuthenticationProviderTest {
    private static final String APPLICATION_NAME = "application_name";
    private static final String APPLICATION_DOMAIN = "application_domain";
    private static final UUID USER_UUID = UUID.randomUUID();
    private static final String USER_ROLE = "ROLE_USER";

    @Mock
    private AuthenticationService authenticationService;

    @Mock
    private UnboundTokenService<TokenType.HmacSha1> unboundTokenService;

    @Mock
    private TokenRepository tokenRepository;

    private AuthenticationToken<EntityType.Combined, TokenType.Simple> combinedToken;
    private TokenProxy<EntityType.Combined, TokenType.Simple> tokenProxy;
    private UUID applicationAuthenticationUuid;

    @Before
    public void initialise() throws IOException, HodErrorException {
        tokenProxy = new TokenProxy<>(EntityType.Combined.INSTANCE, TokenType.Simple.INSTANCE);
        applicationAuthenticationUuid = UUID.randomUUID();

        combinedToken = new AuthenticationToken<>(
                EntityType.Combined.INSTANCE,
                TokenType.Simple.INSTANCE,
                DateTime.now().plus(Hours.TWO),
                "token-id",
                "token-secret",
                DateTime.now().plus(Hours.ONE)
        );

        when(tokenRepository.insert(combinedToken)).thenReturn(tokenProxy);
        when(unboundTokenService.getAuthenticationUuid()).thenReturn(applicationAuthenticationUuid);
    }

    @Test
    public void supportsHodTokenAuthentication() {
        final CookieHodAuthenticationProvider provider = createSimpleProvider();
        assertThat(provider.supports(HodTokenAuthentication.class), is(true));
    }

    @Test
    public void doesNotSupportGeneralAuthentication() {
        final CookieHodAuthenticationProvider provider = createSimpleProvider();
        assertThat(provider.supports(Authentication.class), is(false));
    }

    @Test(expected = BadCredentialsException.class)
    public void failsAuthenticationIfCombinedTokenInvalid() throws HodErrorException {
        final HodError hodError = new HodError.Builder()
                .setErrorCode(HodErrorCode.AUTHENTICATION_FAILED)
                .setDetail("Authentication failed")
                .build();

        when(authenticationService.getCombinedTokenInformation(combinedToken)).thenThrow(new HodErrorException(hodError, 401));

        final CookieHodAuthenticationProvider provider = createSimpleProvider();
        provider.authenticate(new HodTokenAuthentication<>(combinedToken));
    }

    @Test(expected = BadCredentialsException.class)
    public void failsAuthenticationIfCombinedTokenApplicationAuthenticationUuidIncorrect() throws HodErrorException {
        // For this test, this shouldn't be the same as the applicationAuthenticationUuid returned from the unbound service
        final UUID incorrectUuid = UUID.randomUUID();
        final CombinedTokenInformation combinedTokenInformation = createCombinedTokenInformation(incorrectUuid);

        when(authenticationService.getCombinedTokenInformation(combinedToken)).thenReturn(combinedTokenInformation);

        final CookieHodAuthenticationProvider provider = createSimpleProvider();
        provider.authenticate(new HodTokenAuthentication<>(combinedToken));
    }

    @Test
    public void authenticatesWithRole() throws HodErrorException, IOException {
        when(authenticationService.getCombinedTokenInformation(combinedToken)).thenReturn(createCombinedTokenInformation(applicationAuthenticationUuid));

        final CookieHodAuthenticationProvider provider = createSimpleProvider();

        @SuppressWarnings("unchecked")
        final HodAuthentication<EntityType.Combined> authentication = (HodAuthentication<EntityType.Combined>) provider.authenticate(new HodTokenAuthentication(combinedToken));

        verify(tokenRepository, times(1)).insert(combinedToken);

        assertThat(authentication.getTokenProxy(), is(tokenProxy));

        final HodAuthenticationPrincipal principal = authentication.getPrincipal();

        assertThat(principal.getApplication().getName(), is(APPLICATION_NAME));
        assertThat(principal.getUserUuid(), is(USER_UUID));
        assertThat(principal.getUserMetadata().size(), is(0));

        final Collection<GrantedAuthority> authorities = authentication.getAuthorities();

        assertThat(authorities, containsInAnyOrder(
                new SimpleGrantedAuthority(USER_ROLE),
                new HodApplicationGrantedAuthority(new ResourceName(APPLICATION_DOMAIN, APPLICATION_NAME))
        ));
    }

    @Test
    public void authenticatesWithAuthoritiesResolver() throws HodErrorException {
        when(authenticationService.getCombinedTokenInformation(combinedToken)).thenReturn(createCombinedTokenInformation(applicationAuthenticationUuid));

        final GrantedAuthoritiesResolver resolver = (proxy, combinedTokenInformation) -> ImmutableList.<GrantedAuthority>builder()
                .add(new SimpleGrantedAuthority("ROLE_1"))
                .add(new SimpleGrantedAuthority("ROLE_2"))
                .build();

        final AuthenticationProvider provider = new CookieHodAuthenticationProvider(tokenRepository, resolver, authenticationService, unboundTokenService);
        final Authentication authentication = provider.authenticate(new HodTokenAuthentication<>(combinedToken));

        assertThat(authentication.getAuthorities(), containsInAnyOrder(
                new SimpleGrantedAuthority("ROLE_1"),
                new SimpleGrantedAuthority("ROLE_2"),
                new HodApplicationGrantedAuthority(new ResourceName(APPLICATION_DOMAIN, APPLICATION_NAME))
        ));
    }

    private CookieHodAuthenticationProvider createSimpleProvider() {
        return new CookieHodAuthenticationProvider(tokenRepository, USER_ROLE, authenticationService, unboundTokenService);
    }

    private CombinedTokenInformation createCombinedTokenInformation(final UUID applicationAuthenticationUuid) {
        final AuthenticationInformation applicationAuthenticationInformation = new AuthenticationInformation(applicationAuthenticationUuid, AuthenticationType.LEGACY_API_KEY);
        final AuthenticationInformation userAuthenticationInformation = new AuthenticationInformation(UUID.randomUUID(), AuthenticationType.LEGACY_API_KEY);

        final ApplicationInformation applicationInformation = new ApplicationInformation(APPLICATION_NAME, APPLICATION_DOMAIN, applicationAuthenticationInformation);
        final Resource userStore = Resource.builder().uuid(UUID.randomUUID()).name("user_store_name").domain("user_store_domain").build();
        final Account account = new Account(Account.Type.EMAIL, "meg.whitman@hpe.com", Account.Status.CONFIRMED, true);
        final Resource groupUserStore = Resource.builder().uuid(UUID.randomUUID()).name("user_store_name").domain("user_store_domain").build();
        final GroupInformation groupInformation = new GroupInformation(groupUserStore, Collections.singleton("ceo"));
        final UserInformation userInformation = new UserInformation(USER_UUID, userAuthenticationInformation, Collections.singletonList(account), Collections.singletonList(groupInformation));

        return new CombinedTokenInformation(UUID.randomUUID(), applicationInformation, userStore, userInformation);
    }
}
