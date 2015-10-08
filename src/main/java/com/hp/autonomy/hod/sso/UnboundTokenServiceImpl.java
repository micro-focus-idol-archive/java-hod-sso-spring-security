/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.hod.client.api.authentication.ApiKey;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationService;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.error.HodErrorException;
import org.joda.time.ReadablePeriod;
import org.joda.time.Seconds;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Default implementation of UnboundTokenService. This implementation will cache the unbound token until it expires.
 *
 * This class is thread safe.
 */
public class UnboundTokenServiceImpl<T extends TokenType> implements UnboundTokenService<T> {
    // Time before token expiry before we fetch a new token
    static final ReadablePeriod EXPIRY_TOLERANCE = Seconds.seconds(10);

    private final AtomicReference<AuthenticationToken<EntityType.Unbound, T>> unboundTokenCache = new AtomicReference<>(null);
    private final Object lock = new Object();

    private final ConfigService<? extends HodSsoConfig> configService;
    private final T tokenType;
    private final AuthenticationService authenticationService;

    /**
     * Creates a new UnboundTokenServiceImpl
     * @param authenticationService The authentication service to use to require the unbound token
     * @param configService The service used to obtain the configuration
     */
    public UnboundTokenServiceImpl(
        final AuthenticationService authenticationService,
        final ConfigService<? extends HodSsoConfig> configService,
        final T tokenType
    ) {
        this.authenticationService = authenticationService;
        this.configService = configService;
        this.tokenType = tokenType;
    }

    @Override
    public AuthenticationToken<EntityType.Unbound, T> getUnboundToken() throws HodErrorException {
        AuthenticationToken<EntityType.Unbound, T> unboundToken = unboundTokenCache.get();

        if (isTokenValid(unboundToken)) {
            return unboundToken;
        } else {
            synchronized (lock) {
                unboundToken = unboundTokenCache.get();

                // Check that the token is valid again because another thread might have updated it
                if (isTokenValid(unboundToken)) {
                    return unboundToken;
                } else {
                    unboundToken = authenticationService.authenticateUnbound(getApiKey(), tokenType);

                    unboundTokenCache.set(unboundToken);

                    return unboundToken;
                }
            }
        }
    }

    private boolean isTokenValid(final AuthenticationToken<EntityType.Unbound, T> unboundToken) {
        return unboundToken != null && unboundToken.getExpiry().minus(EXPIRY_TOLERANCE).isAfterNow();
    }

    private ApiKey getApiKey() {
        return new ApiKey(configService.getConfig().getApiKey());
    }
}
