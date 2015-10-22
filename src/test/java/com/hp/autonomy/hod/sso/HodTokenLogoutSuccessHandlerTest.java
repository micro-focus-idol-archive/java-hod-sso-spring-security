package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationType;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.AuthenticationInformation;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.UserStoreInformation;
import com.hp.autonomy.hod.client.api.resource.ResourceIdentifier;
import com.hp.autonomy.hod.client.token.TokenProxy;
import com.hp.autonomy.hod.client.token.TokenRepository;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.UUID;

import static org.joda.time.Duration.standardHours;
import static org.mockito.Mockito.*;

public class HodTokenLogoutSuccessHandlerTest {
    private static final String CONTEXT_PATH = "/context";
    private static final String REDIRECT_PATH = "/logout-success";

    private TokenProxy<EntityType.Combined, TokenType.Simple> tokenProxy;
    private HodTokenLogoutSuccessHandler logoutSuccessHandler;

    @Before
    public void setUp() throws IOException {
        tokenProxy = new TokenProxy<>(EntityType.Combined.INSTANCE, TokenType.Simple.INSTANCE);

        final AuthenticationToken<EntityType.Combined, TokenType.Simple> token = new AuthenticationToken<>(
                EntityType.Combined.INSTANCE,
                TokenType.Simple.INSTANCE,
                DateTime.now().plus(standardHours(2)),
                "token-id",
                "token-secret",
                DateTime.now().plus(standardHours(1))
        );

        final TokenRepository tokenRepository = mock(TokenRepository.class);
        when(tokenRepository.get(tokenProxy)).thenReturn(token);

        logoutSuccessHandler = new HodTokenLogoutSuccessHandler(REDIRECT_PATH, tokenRepository);
    }

    @Test
    public void redirectsWithNoAuthentication() throws IOException, ServletException {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getContextPath()).thenReturn(CONTEXT_PATH);

        final String mockRedirectUrl = "/mock/redirect/url";
        final HttpServletResponse response = mock(HttpServletResponse.class);

        final String expectedPath = CONTEXT_PATH + REDIRECT_PATH;
        when(response.encodeRedirectURL(expectedPath)).thenReturn(mockRedirectUrl);

        logoutSuccessHandler.onLogoutSuccess(request, response, null);

        verify(response).sendRedirect(mockRedirectUrl);
    }

    @Test
    public void redirectsWithAuthentication() throws IOException, ServletException {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getContextPath()).thenReturn(CONTEXT_PATH);

        final String mockRedirectUrl = "/mock/redirect/url";
        final HttpServletResponse response = mock(HttpServletResponse.class);

        final String expectedPath = CONTEXT_PATH + REDIRECT_PATH + "?token=CMB%3ASIMPLE%3Atoken-id%3Atoken-secret";
        when(response.encodeRedirectURL(expectedPath)).thenReturn(mockRedirectUrl);

        final HodAuthenticationPrincipal principal = new HodAuthenticationPrincipal(
                UUID.randomUUID(),
                UUID.randomUUID(),
                new ResourceIdentifier("APP-DOMAIN", "APP-NAME"),
                new UserStoreInformation(UUID.randomUUID(), "STORE-DOMAIN", "STORE-NAME"),
                new AuthenticationInformation(UUID.randomUUID(), AuthenticationType.LEGACY_API_KEY),
                new AuthenticationInformation(UUID.randomUUID(), AuthenticationType.LEGACY_API_KEY),
                null
        );

        final HodAuthentication authentication = new HodAuthentication(
                tokenProxy,
                Collections.<GrantedAuthority>emptySet(),
                principal
        );

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);

        verify(response).sendRedirect(mockRedirectUrl);
    }
}
