/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.hod.client.api.authentication.ApiKey;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationService;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationType;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.AuthenticationInformation;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.UnboundTokenInformation;
import com.hp.autonomy.hod.client.error.HodError;
import com.hp.autonomy.hod.client.error.HodErrorException;
import org.joda.time.DateTime;
import org.joda.time.Days;
import org.joda.time.Hours;
import org.joda.time.Period;
import org.joda.time.ReadablePeriod;
import org.joda.time.Seconds;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.mockito.stubbing.OngoingStubbing;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UnboundTokenServiceImplTest {
    private static final String API_KEY = "123-api-key";
    private static final UUID AUTH_UUID = UUID.randomUUID();

    private ExecutorService executorService;

    private AuthenticationService authenticationService;

    private UnboundTokenService<TokenType.HmacSha1> unboundTokenService;

    @Before
    public void setUp() throws HodErrorException, InterruptedException {
        executorService = Executors.newFixedThreadPool(8);

        final HodSsoConfig config = mock(HodSsoConfig.class);
        when(config.getApiKey()).thenReturn(API_KEY);

        @SuppressWarnings("unchecked")
        final ConfigService<? extends HodSsoConfig> configService = mock(ConfigService.class);

        when(configService.getConfig()).thenReturn(config);

        authenticationService = mock(AuthenticationService.class);

        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> initialToken = createToken(Seconds.ZERO);
        mockAuthenticateUnbound().thenReturn(initialToken);

        final UnboundTokenInformation tokenInformation = new UnboundTokenInformation(new AuthenticationInformation(AUTH_UUID, AuthenticationType.LEGACY_API_KEY));
        when(authenticationService.getHmacUnboundTokenInformation(initialToken)).thenReturn(tokenInformation);

        unboundTokenService = new UnboundTokenServiceImpl(authenticationService, configService);
    }

    @After
    public void tearDown() {
        executorService.shutdownNow();
    }

    @Test
    public void getsAuthenticationUUID() {
        assertThat(unboundTokenService.getAuthenticationUuid(), is(AUTH_UUID));
    }

    @Test
    public void getsNewUnboundToken() throws InterruptedException, HodErrorException {
        final CountDownLatch latch = new CountDownLatch(1);
        final List<UnboundTokenOutput> outputs = Collections.synchronizedList(new ArrayList<UnboundTokenOutput>());

        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken = createToken(Hours.ONE);
        mockAuthenticateUnbound().then(new DelayedAnswer<>(unboundToken));

        executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch));
        latch.await();

        assertThat(outputs, hasSize(1));
        verify(authenticationService, times(2)).authenticateUnbound(any(ApiKey.class), eq(TokenType.HmacSha1.INSTANCE));
        checkOutput(outputs.get(0), unboundToken, null);
    }

    @Test
    public void getsUnboundTokenFiveTimesButOnlyFetchesOnce() throws HodErrorException, InterruptedException {
        final int times = 5;
        final CountDownLatch latch = new CountDownLatch(times);
        final List<UnboundTokenOutput> outputs = Collections.synchronizedList(new ArrayList<UnboundTokenOutput>());

        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken = createToken(Hours.ONE);
        mockAuthenticateUnbound().then(new DelayedAnswer<>(unboundToken));

        for (int i = 0; i < times; i++) {
            executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch));
        }

        latch.await();

        assertThat(outputs, hasSize(times));
        verify(authenticationService, times(2)).authenticateUnbound(any(ApiKey.class), eq(TokenType.HmacSha1.INSTANCE));

        for (int i = 0; i < times; i++) {
            checkOutput(outputs.get(i), unboundToken, null);
        }
    }

    @Test
    public void getsUnboundTokenAfterException() throws HodErrorException, InterruptedException {
        final List<UnboundTokenOutput> outputs = Collections.synchronizedList(new ArrayList<UnboundTokenOutput>());
        final CountDownLatch latch = new CountDownLatch(3);

        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken = createToken(Hours.ONE);
        final HodErrorException exception = createException();
        mockAuthenticateUnbound().then(new DelayedAnswer<>(exception)).then(new DelayedAnswer<>(unboundToken));

        for (int i = 0; i < 3; i++) {
            executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch));
        }

        latch.await();

        assertThat(outputs, hasSize(3));
        verify(authenticationService, times(3)).authenticateUnbound(any(ApiKey.class), eq(TokenType.HmacSha1.INSTANCE));

        checkOutput(outputs.get(0), null, exception);
        checkOutput(outputs.get(1), unboundToken, null);
        checkOutput(outputs.get(2), unboundToken, null);
    }

    @Test
    public void fetchesWhenTokenExpires() throws InterruptedException, HodErrorException {
        final List<UnboundTokenOutput> outputs = Collections.synchronizedList(new ArrayList<UnboundTokenOutput>());

        // The first token is created just before it expires so the second call to getUnboundToken should fetch again
        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> expiredUnboundToken = createToken(new Period(UnboundTokenServiceImpl.EXPIRY_TOLERANCE).plus(Seconds.ONE));
        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> newToken = createToken(Days.ONE);
        mockAuthenticateUnbound().then(new DelayedAnswer<>(expiredUnboundToken)).then(new DelayedAnswer<>(newToken));

        final CountDownLatch latch1 = new CountDownLatch(1);
        executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch1));
        latch1.await();

        // Wait for the first token to be expired
        TimeUnit.SECONDS.sleep(2);

        final CountDownLatch latch2 = new CountDownLatch(1);
        executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch2));
        latch2.await();

        assertThat(outputs, hasSize(2));
        verify(authenticationService, times(3)).authenticateUnbound(any(ApiKey.class), eq(TokenType.HmacSha1.INSTANCE));

        checkOutput(outputs.get(0), expiredUnboundToken, null);
        checkOutput(outputs.get(1), newToken, null);
    }

    private OngoingStubbing<AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1>> mockAuthenticateUnbound() throws HodErrorException {
        return when(authenticationService.authenticateUnbound(new ApiKey(API_KEY), TokenType.HmacSha1.INSTANCE));
    }

    private void checkOutput(final UnboundTokenOutput output, final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken, final HodErrorException exception) {
        assertThat(output.exception, is(exception));
        assertThat(output.unboundToken, is(unboundToken));
    }

    private AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> createToken(final ReadablePeriod expiryOffset) {
        final DateTime expiry = DateTime.now().plus(expiryOffset);
        return new AuthenticationToken<>(EntityType.Unbound.INSTANCE, TokenType.HmacSha1.INSTANCE, expiry, "id-" + UUID.randomUUID(), "secret", new DateTime(0));
    }

    private HodErrorException createException() {
        final HodError hodError = new HodError.Builder().build();
        return new HodErrorException(hodError, 500);
    }

    private static class UnboundTokenOutput {
        private final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken;
        private final HodErrorException exception;

        private UnboundTokenOutput(final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken, final HodErrorException exception) {
            this.unboundToken = unboundToken;
            this.exception = exception;
        }
    }

    private static class DelayedAnswer<T> implements Answer<T> {
        private final T output;

        private DelayedAnswer(final T output) {
            this.output = output;
        }

        @Override
        public T answer(final InvocationOnMock invocation) throws Throwable {
            Thread.sleep(500);

            if (output instanceof Throwable) {
                throw (Throwable) output;
            }

            return output;
        }
    }

    private static class UnboundTokenGetter implements Runnable {
        private final UnboundTokenService<TokenType.HmacSha1> unboundTokenService;
        private final List<UnboundTokenOutput> outputs;
        private final CountDownLatch latch;

        private UnboundTokenGetter(final UnboundTokenService<TokenType.HmacSha1> unboundTokenService, final List<UnboundTokenOutput> outputs, final CountDownLatch latch) {
            this.unboundTokenService = unboundTokenService;
            this.outputs = outputs;
            this.latch = latch;
        }

        @Override
        public void run() {
            AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken = null;
            HodErrorException exception = null;

            try {
                unboundToken = unboundTokenService.getUnboundToken();
            } catch (final HodErrorException e) {
                exception = e;
            }

            outputs.add(new UnboundTokenOutput(unboundToken, exception));

            latch.countDown();
        }
    }

}