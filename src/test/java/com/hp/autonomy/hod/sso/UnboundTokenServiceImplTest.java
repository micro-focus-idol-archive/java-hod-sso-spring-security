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
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

public class UnboundTokenServiceImplTest {
    private static final String API_KEY = "123-api-key";
    private static final UUID AUTH_UUID = UUID.randomUUID();
    private static final long TIME_OUT_SECONDS = 3;

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
        unboundTokenService = new UnboundTokenServiceImpl(authenticationService, configService);
    }

    @After
    public void tearDown() {
        executorService.shutdownNow();
    }

    @Test
    public void getsAuthenticationUUID() throws HodErrorException {
        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> token = createToken(Hours.ONE);
        mockAuthenticateUnbound().thenReturn(token);
        mockTokenInformation(token);

        assertThat(unboundTokenService.getAuthenticationUuid(), is(AUTH_UUID));
    }

    @Test
    public void getsNewUnboundToken() throws InterruptedException, HodErrorException {
        final CountDownLatch latch = new CountDownLatch(1);
        final List<Try<AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1>>> outputs = Collections.synchronizedList(new ArrayList<Try<AuthenticationToken<EntityType.Unbound,TokenType.HmacSha1>>>());

        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken = createToken(Hours.ONE);
        mockAuthenticateUnbound().then(new DelayedAnswer<>(unboundToken));
        mockTokenInformation(unboundToken);

        executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch));
        awaitLatch(latch);

        assertThat(outputs, hasSize(1));
        verify(authenticationService, times(1)).authenticateUnbound(any(ApiKey.class), eq(TokenType.HmacSha1.INSTANCE));
        checkOutput(outputs.get(0), unboundToken, null);
    }

    @Test
    public void getsUnboundTokenFiveTimesButOnlyFetchesOnce() throws HodErrorException, InterruptedException {
        final int times = 5;
        final CountDownLatch latch = new CountDownLatch(times);
        final List<Try<AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1>>> outputs = Collections.synchronizedList(new ArrayList<Try<AuthenticationToken<EntityType.Unbound,TokenType.HmacSha1>>>());

        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken = createToken(Hours.ONE);
        mockAuthenticateUnbound().then(new DelayedAnswer<>(unboundToken));
        mockTokenInformation(unboundToken);

        for (int i = 0; i < times; i++) {
            executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch));
        }

        awaitLatch(latch);

        assertThat(outputs, hasSize(times));
        verify(authenticationService, times(1)).authenticateUnbound(any(ApiKey.class), eq(TokenType.HmacSha1.INSTANCE));

        for (int i = 0; i < times; i++) {
            checkOutput(outputs.get(i), unboundToken, null);
        }
    }

    @Test
    public void getsUnboundTokenAndUUIDButOnlyFetchesOnce() throws HodErrorException, InterruptedException {
        final int times = 2;
        final CountDownLatch latch = new CountDownLatch(times);
        final List<Try<AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1>>> tokenOutputs = Collections.synchronizedList(new ArrayList<Try<AuthenticationToken<EntityType.Unbound,TokenType.HmacSha1>>>());
        final List<Try<UUID>> authenticationUUIDOutputs = Collections.synchronizedList(new ArrayList<Try<UUID>>());

        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken = createToken(Hours.ONE);
        mockAuthenticateUnbound().then(new DelayedAnswer<>(unboundToken));
        mockTokenInformation(unboundToken);

        executorService.execute(new UnboundTokenGetter(unboundTokenService, tokenOutputs, latch));
        executorService.execute(new UnboundAuthenticationUUIDGetter(unboundTokenService, authenticationUUIDOutputs, latch));

        awaitLatch(latch);

        assertThat(tokenOutputs, hasSize(1));
        assertThat(authenticationUUIDOutputs, hasSize(1));
        verify(authenticationService, times(1)).authenticateUnbound(any(ApiKey.class), eq(TokenType.HmacSha1.INSTANCE));

        checkOutput(tokenOutputs.get(0), unboundToken, null);
        checkOutput(authenticationUUIDOutputs.get(0), AUTH_UUID, null);
    }

    @Test
    public void getsUnboundTokenAfterException() throws HodErrorException, InterruptedException {
        final List<Try<AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1>>> outputs = Collections.synchronizedList(new ArrayList<Try<AuthenticationToken<EntityType.Unbound,TokenType.HmacSha1>>>());
        final CountDownLatch latch = new CountDownLatch(3);

        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken = createToken(Hours.ONE);
        final HodErrorException exception = createException();
        mockAuthenticateUnbound().then(new DelayedAnswer<>(exception)).then(new DelayedAnswer<>(unboundToken));
        mockTokenInformation(unboundToken);

        for (int i = 0; i < 3; i++) {
            executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch));
        }

        awaitLatch(latch);

        assertThat(outputs, hasSize(3));
        verify(authenticationService, times(2)).authenticateUnbound(any(ApiKey.class), eq(TokenType.HmacSha1.INSTANCE));

        checkOutput(outputs.get(0), null, exception);
        checkOutput(outputs.get(1), unboundToken, null);
        checkOutput(outputs.get(2), unboundToken, null);
    }

    @Test
    public void fetchesWhenTokenExpires() throws InterruptedException, HodErrorException {
        final List<Try<AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1>>> outputs = Collections.synchronizedList(new ArrayList<Try<AuthenticationToken<EntityType.Unbound,TokenType.HmacSha1>>>());

        // The first token is created just before it expires so the second call to getUnboundToken should fetch again
        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> expiredUnboundToken = createToken(new Period(UnboundTokenServiceImpl.EXPIRY_TOLERANCE).plus(Seconds.ONE));
        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> newToken = createToken(Days.ONE);
        mockAuthenticateUnbound().then(new DelayedAnswer<>(expiredUnboundToken)).then(new DelayedAnswer<>(newToken));
        mockTokenInformation(expiredUnboundToken);

        final CountDownLatch latch1 = new CountDownLatch(1);
        executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch1));
        awaitLatch(latch1);

        // Wait for the first token to be expired
        TimeUnit.SECONDS.sleep(2);

        final CountDownLatch latch2 = new CountDownLatch(1);
        executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch2));
        awaitLatch(latch2);

        assertThat(outputs, hasSize(2));
        verify(authenticationService, times(2)).authenticateUnbound(any(ApiKey.class), eq(TokenType.HmacSha1.INSTANCE));

        checkOutput(outputs.get(0), expiredUnboundToken, null);
        checkOutput(outputs.get(1), newToken, null);
    }

    private void awaitLatch(final CountDownLatch latch) throws InterruptedException {
        final boolean completed = latch.await(TIME_OUT_SECONDS, TimeUnit.SECONDS);
        assertTrue("Latch was not counted down", completed);
    }

    private OngoingStubbing<AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1>> mockAuthenticateUnbound() throws HodErrorException {
        return when(authenticationService.authenticateUnbound(new ApiKey(API_KEY), TokenType.HmacSha1.INSTANCE));
    }

    private <T> void checkOutput(final Try<T> actual, final T expectation, final HodErrorException exception) {
        assertThat(actual.exception, is(exception));
        assertThat(actual.output, is(expectation));
    }

    private AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> createToken(final ReadablePeriod expiryOffset) {
        final DateTime expiry = DateTime.now().plus(expiryOffset);
        return new AuthenticationToken<>(EntityType.Unbound.INSTANCE, TokenType.HmacSha1.INSTANCE, expiry, "id-" + UUID.randomUUID(), "secret", new DateTime(0));
    }

    private HodErrorException createException() {
        final HodError hodError = new HodError.Builder().build();
        return new HodErrorException(hodError, 500);
    }

    private void mockTokenInformation(AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> token) throws HodErrorException {
        final UnboundTokenInformation tokenInformation = new UnboundTokenInformation(new AuthenticationInformation(AUTH_UUID, AuthenticationType.LEGACY_API_KEY));
        when(authenticationService.getHmacUnboundTokenInformation(token)).thenReturn(tokenInformation);
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

    private static class Try<T> {
        private final T output;
        private final HodErrorException exception;

        private Try(final T output, final HodErrorException exception) {
            this.output = output;
            this.exception = exception;
        }
    }

    private interface UnboundTokenServiceAction<T> {
        T callService(UnboundTokenService<TokenType.HmacSha1> service) throws HodErrorException;
    }

    private static class UnboundTokenServiceRunnable<T> implements Runnable {
        private final UnboundTokenService<TokenType.HmacSha1> unboundTokenService;
        private final UnboundTokenServiceAction<T> action;
        private final List<Try<T>> outputs;
        private final CountDownLatch latch;

        private UnboundTokenServiceRunnable(final UnboundTokenService<TokenType.HmacSha1> unboundTokenService, final List<Try<T>> outputs, final CountDownLatch latch, final UnboundTokenServiceAction<T> action) {
            this.unboundTokenService = unboundTokenService;
            this.outputs = outputs;
            this.latch = latch;
            this.action = action;
        }

        @Override
        public void run() {
            T unboundToken = null;
            HodErrorException exception = null;

            try {
                unboundToken = action.callService(unboundTokenService);
            } catch (final HodErrorException e) {
                exception = e;
            }

            outputs.add(new Try<>(unboundToken, exception));

            latch.countDown();
        }
    }

    private static class UnboundTokenGetter extends UnboundTokenServiceRunnable<AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1>> {
        private UnboundTokenGetter(final UnboundTokenService<TokenType.HmacSha1> unboundTokenService, final List<Try<AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1>>> outputs, final CountDownLatch latch) {
            super(unboundTokenService, outputs, latch, new UnboundTokenServiceAction<AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1>>() {
                @Override
                public AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> callService(UnboundTokenService<TokenType.HmacSha1> service) throws HodErrorException {
                    return service.getUnboundToken();
                }
            });
        }
    }

    private static class UnboundAuthenticationUUIDGetter extends UnboundTokenServiceRunnable<UUID> {
        private UnboundAuthenticationUUIDGetter(final UnboundTokenService<TokenType.HmacSha1> unboundTokenService, final List<Try<UUID>> outputs, final CountDownLatch latch) {
            super(unboundTokenService, outputs, latch, new UnboundTokenServiceAction<UUID>() {
                @Override
                public UUID callService(UnboundTokenService<TokenType.HmacSha1> service) throws HodErrorException {
                    return service.getAuthenticationUuid();
                }
            });
        }
    }

}