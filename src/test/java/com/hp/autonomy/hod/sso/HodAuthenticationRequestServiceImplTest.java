package com.hp.autonomy.hod.sso;

import com.google.common.collect.ImmutableSet;
import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationService;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.SignedRequest;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.error.HodErrorException;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.Set;

import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HodAuthenticationRequestServiceImplTest {
    private static final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> AUTHENTICATION_TOKEN = new AuthenticationToken<>(
            EntityType.Unbound.INSTANCE,
            TokenType.HmacSha1.INSTANCE,
            DateTime.now(),
            "token-id",
            "token-secret",
            DateTime.now()
    );

    private static final Set<String> ALLOWED_ORIGINS = ImmutableSet.<String>builder()
            .add("https://example.com")
            .add("http://127.0.0.1:8080")
            .build();

    private HodAuthenticationRequestService requestService;
    private AuthenticationService authenticationService;

    @Before
    public void initialise() throws HodErrorException, MalformedURLException {
        final HodSsoConfig config = mock(HodSsoConfig.class);
        when(config.getAllowedOrigins()).thenReturn(ALLOWED_ORIGINS);
        when(config.getSsoUrl()).thenReturn(new URL("https://dev.havenondemand.com/sso.html"));

        final ConfigService<HodSsoConfig> configService = mock(ConfigService.class);
        when(configService.getConfig()).thenReturn(config);

        authenticationService = mock(AuthenticationService.class);

        final UnboundTokenService<TokenType.HmacSha1> unboundTokenService = mock(UnboundTokenService.class);
        when(unboundTokenService.getUnboundToken()).thenReturn(AUTHENTICATION_TOKEN);

        requestService = new HodAuthenticationRequestServiceImpl(
                configService,
                authenticationService,
                unboundTokenService
        );
    }

    @Test
    public void getCombinedPatchRequest() throws HodErrorException {
        final SignedRequest expectedOutput = mock(SignedRequest.class);
        when(authenticationService.combinedPatchRequest(Matchers.any(), eq(AUTHENTICATION_TOKEN))).thenReturn(expectedOutput);

        assertSame(expectedOutput, requestService.getCombinedPatchRequest());
    }

    @Test
    public void getSsoPageCombinedPatchRequest() throws HodErrorException, MalformedURLException, InvalidOriginException {
        final URL redirectUrl = new URL("http://127.0.0.1:8080/sso");

        when(authenticationService.combinedPatchRequest(Matchers.any(), Matchers.any(), eq(AUTHENTICATION_TOKEN))).thenAnswer(invocationOnMock -> {
            final Object[] arguments = invocationOnMock.getArguments();
            // If the AuthenticationService was passed the correct arguments, return a SignedRequest, otherwise, return null
            return Collections.singleton("https://dev.havenondemand.com").equals(arguments[0]) && redirectUrl.toString().equals(arguments[1]) ? mock(SignedRequest.class) : null;
        });

        final SignedRequest output = requestService.getSsoPageCombinedPatchRequest(redirectUrl);

        // If not null, the AuthenticationService was given the correct arguments
        assertThat(output, not(nullValue()));
    }

    @Test(expected = InvalidOriginException.class)
    public void getSsoPageCombinedPatchRequestInvalidRedirectPort() throws MalformedURLException, HodErrorException, InvalidOriginException {
        requestService.getSsoPageCombinedPatchRequest(new URL("http://127.0.0.1:8090/sso"));
    }

    @Test(expected = InvalidOriginException.class)
    public void getSsoPageCombinedPatchRequestInvalidRedirectHost() throws MalformedURLException, HodErrorException, InvalidOriginException {
        requestService.getSsoPageCombinedPatchRequest(new URL("https://notallowed.example.com/sso"));
    }

    @Test(expected = InvalidOriginException.class)
    public void getSsoPageCombinedPatchRequestInvalidProtocol() throws MalformedURLException, HodErrorException, InvalidOriginException {
        requestService.getSsoPageCombinedPatchRequest(new URL("http://example.com/login?secure=false"));
    }
}