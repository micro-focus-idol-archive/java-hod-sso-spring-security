/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.frontend.abc.configuration.AbcHostedConfig;
import com.hp.autonomy.frontend.abc.configuration.HodConfig;
import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.hod.client.api.authentication.ApiKey;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationService;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
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
import org.junit.runner.RunWith;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.mockito.stubbing.OngoingStubbing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(loader = AnnotationConfigContextLoader.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class UnboundTokenServiceTest {
    private static final String API_KEY = "123-api-key";

    private ExecutorService executorService;

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private UnboundTokenService unboundTokenService;

    @Before
    public void setUp() {
        executorService = Executors.newFixedThreadPool(8);
    }

    @After
    public void tearDown() {
        executorService.shutdownNow();
    }

    @Test
    public void getsUnboundToken() throws InterruptedException, HodErrorException {
        final CountDownLatch latch = new CountDownLatch(1);
        final List<UnboundTokenOutput> outputs = Collections.synchronizedList(new ArrayList<UnboundTokenOutput>());

        final AuthenticationToken unboundToken = createToken(Hours.ONE);
        mockAuthenticateUnbound().then(new DelayedAnswer<>(unboundToken));

        executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch));
        latch.await();

        assertThat(outputs, hasSize(1));
        verify(authenticationService, times(1)).authenticateUnbound(any(ApiKey.class));
        checkOutput(outputs.get(0), unboundToken, null);
    }

    @Test
    public void getsUnboundTokenFiveTimesButOnlyFetchesOnce() throws HodErrorException, InterruptedException {
        final int times = 5;
        final CountDownLatch latch = new CountDownLatch(times);
        final List<UnboundTokenOutput> outputs = Collections.synchronizedList(new ArrayList<UnboundTokenOutput>());

        final AuthenticationToken unboundToken = createToken(Hours.ONE);
        mockAuthenticateUnbound().then(new DelayedAnswer<>(unboundToken));

        for (int i = 0; i < times; i++) {
            executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch));
        }

        latch.await();

        assertThat(outputs, hasSize(times));
        verify(authenticationService, times(1)).authenticateUnbound(any(ApiKey.class));

        for (int i = 0; i < times; i++) {
            checkOutput(outputs.get(i), unboundToken, null);
        }
    }

    @Test
    public void getsUnboundTokenAfterException() throws HodErrorException, InterruptedException {
        final List<UnboundTokenOutput> outputs = Collections.synchronizedList(new ArrayList<UnboundTokenOutput>());
        final CountDownLatch latch = new CountDownLatch(3);

        final AuthenticationToken unboundToken = createToken(Hours.ONE);
        final HodErrorException exception = createException();
        mockAuthenticateUnbound().then(new DelayedAnswer<>(exception)).then(new DelayedAnswer<>(unboundToken));

        for (int i = 0; i < 3; i++) {
            executorService.execute(new UnboundTokenGetter(unboundTokenService, outputs, latch));
        }

        latch.await();

        assertThat(outputs, hasSize(3));
        verify(authenticationService, times(2)).authenticateUnbound(any(ApiKey.class));

        checkOutput(outputs.get(0), null, exception);
        checkOutput(outputs.get(1), unboundToken, null);
        checkOutput(outputs.get(2), unboundToken, null);
    }

    @Test
    public void fetchesWhenTokenExpires() throws InterruptedException, HodErrorException {
        final List<UnboundTokenOutput> outputs = Collections.synchronizedList(new ArrayList<UnboundTokenOutput>());

        // The first token is created just before it expires so the second call to getUnboundToken should fetch again
        final AuthenticationToken expiredUnboundToken = createToken(new Period(UnboundTokenServiceImpl.EXPIRY_TOLERANCE).plus(Seconds.ONE));
        final AuthenticationToken newToken = createToken(Days.ONE);
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
        verify(authenticationService, times(2)).authenticateUnbound(any(ApiKey.class));

        checkOutput(outputs.get(0), expiredUnboundToken, null);
        checkOutput(outputs.get(1), newToken, null);
    }

    private OngoingStubbing<AuthenticationToken> mockAuthenticateUnbound() throws HodErrorException {
        return when(authenticationService.authenticateUnbound(new ApiKey(API_KEY)));
    }

    private void checkOutput(final UnboundTokenOutput output, final AuthenticationToken unboundToken, final HodErrorException exception) {
        assertThat(output.exception, is(exception));
        assertThat(output.unboundToken, is(unboundToken));
    }

    private AuthenticationToken createToken(final ReadablePeriod expiryOffset) {
        final long expiry = DateTime.now().plus(expiryOffset).getMillis();
        return new AuthenticationToken(expiry, "id-" + UUID.randomUUID(), "secret", "UNB:HMAC_SHA1", 0);
    }

    private HodErrorException createException() {
        final HodError hodError = new HodError.Builder().build();
        return new HodErrorException(hodError, 500);
    }

    private static class UnboundTokenOutput {
        private final AuthenticationToken unboundToken;
        private final HodErrorException exception;

        private UnboundTokenOutput(final AuthenticationToken unboundToken, final HodErrorException exception) {
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
        private final UnboundTokenService unboundTokenService;
        private final List<UnboundTokenOutput> outputs;
        private final CountDownLatch latch;

        private UnboundTokenGetter(final UnboundTokenService unboundTokenService, final List<UnboundTokenOutput> outputs, final CountDownLatch latch) {
            this.unboundTokenService = unboundTokenService;
            this.outputs = outputs;
            this.latch = latch;
        }

        @Override
        public void run() {
            AuthenticationToken unboundToken = null;
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

    @Configuration
    static class ContextConfiguration {
        @Bean
        public ConfigService<AbcHostedConfig> configService() {
            final HodConfig hod = mock(HodConfig.class);
            when(hod.getApiKey()).thenReturn(API_KEY);

            final AbcHostedConfig config = mock(AbcHostedConfig.class);
            when(config.getHod()).thenReturn(hod);

            @SuppressWarnings("unchecked")
            final ConfigService<AbcHostedConfig> configService = mock(ConfigService.class);

            when(configService.getConfig()).thenReturn(config);
            return configService;
        }

        @Bean
        public AuthenticationService authenticationService() throws HodErrorException {
            return mock(AuthenticationService.class);
        }

        @Bean
        public UnboundTokenService unboundTokenService() {
            return new UnboundTokenServiceImpl();
        }
    }
}