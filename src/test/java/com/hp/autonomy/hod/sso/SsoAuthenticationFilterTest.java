package com.hp.autonomy.hod.sso;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SsoAuthenticationFilterTest {
    private SsoAuthenticationFilter filter;

    @Mock
    private AuthenticationManager authenticationManager;

    @Before
    public void initialise() {
        filter = new SsoAuthenticationFilter("/authenticate");
        filter.setAuthenticationManager(authenticationManager);
        filter.afterPropertiesSet();
    }

    @Test(expected = AuthenticationServiceException.class)
    public void failsWithErrorParameter() throws IOException, ServletException {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("error")).thenReturn("Internal server error");

        filter.attemptAuthentication(request, mock(HttpServletResponse.class));
    }

    @Test
    public void authenticatesWithAuthenticationManager() throws IOException, ServletException {
        final Authentication expectedAuthentication = mock(Authentication.class);
        when(authenticationManager.authenticate(Matchers.<Authentication>any())).thenReturn(expectedAuthentication);

        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("expiry")).thenReturn("1475037954");
        when(request.getParameter("startRefresh")).thenReturn("1475036954");
        when(request.getParameter("type")).thenReturn("CMB_SSO:SIMPLE");
        when(request.getParameter("id")).thenReturn("id-" + UUID.randomUUID().toString());
        when(request.getParameter("secret")).thenReturn("secret-" + UUID.randomUUID().toString());

        final Authentication outputAuthentication = filter.attemptAuthentication(request, mock(HttpServletResponse.class));
        assertSame(expectedAuthentication, outputAuthentication);
    }
}