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
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.UnboundTokenInformation;
import com.hp.autonomy.hod.client.error.HodErrorException;
import org.joda.time.ReadablePeriod;
import org.joda.time.Seconds;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Default implementation of UnboundTokenService. This implementation will cache the unbound token until it expires.
 *
 * This class is thread safe.
 */
public class UnboundTokenServiceImpl implements UnboundTokenService<TokenType.HmacSha1> {
    // Time before token expiry before we fetch a new token
    static final ReadablePeriod EXPIRY_TOLERANCE = Seconds.seconds(10);

    private final Object lock = new Object();

    private final AuthenticationService authenticationService;
    private final AtomicReference<AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1>> unboundTokenCache;
    private final UUID authenticationUuid;
    private final ApiKey apiKey;

    /**
     * Creates a new UnboundTokenServiceImpl, fetching the authentication UUID and an unbound token from Haven OnDemand.
     * @param authenticationService The authentication service to use to require the unbound token
     * @param configService The service used to obtain the configuration
     */
    public UnboundTokenServiceImpl(
        final AuthenticationService authenticationService,
        final ConfigService<? extends HodSsoConfig> configService
    ) throws HodErrorException {
        this.authenticationService = authenticationService;
        apiKey = new ApiKey(configService.getConfig().getApiKey());

        final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken = authenticationService.authenticateUnbound(apiKey, TokenType.HmacSha1.INSTANCE);
        final UnboundTokenInformation information = authenticationService.getHmacUnboundTokenInformation(unboundToken);

        authenticationUuid = information.getAuthentication().getUuid();
        unboundTokenCache = new AtomicReference<>(unboundToken);
    }

    @Override
    public AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> getUnboundToken() throws HodErrorException {
        AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken = unboundTokenCache.get();

        if (isTokenValid(unboundToken)) {
            return unboundToken;
        } else {
            synchronized (lock) {
                unboundToken = unboundTokenCache.get();

                // Check that the token is valid again because another thread might have updated it
                if (isTokenValid(unboundToken)) {
                    return unboundToken;
                } else {
                    unboundToken = authenticationService.authenticateUnbound(apiKey, TokenType.HmacSha1.INSTANCE);

                    unboundTokenCache.set(unboundToken);

                    return unboundToken;
                }
            }
        }
    }

    @Override
    public UUID getAuthenticationUuid() {
        return authenticationUuid;
    }

    private boolean isTokenValid(final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken) {
        return unboundToken.getExpiry().minus(EXPIRY_TOLERANCE).isAfterNow();
    }
}
