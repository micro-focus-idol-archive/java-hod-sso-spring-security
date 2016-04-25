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
import lombok.Data;
import org.joda.time.ReadablePeriod;
import org.joda.time.Seconds;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Default implementation of UnboundTokenService. This implementation will cache the unbound token until it expires.
 * <p/>
 * This class is thread safe.
 */
public class UnboundTokenServiceImpl implements UnboundTokenService<TokenType.HmacSha1> {
    // Time before token expiry before we fetch a new token
    static final ReadablePeriod EXPIRY_TOLERANCE = Seconds.seconds(10);

    private final Object lock = new Object();

    private final AuthenticationService authenticationService;
    private final ConfigService<? extends HodSsoConfig> configService;
    private final AtomicReference<TokenAndUuid> cache = new AtomicReference<>(null);

    /**
     * Creates a new UnboundTokenServiceImpl, fetching the authentication UUID and an unbound token from Haven OnDemand.
     * @param authenticationService The authentication service to use to require the unbound token
     * @param configService         The service used to obtain the configuration
     */
    public UnboundTokenServiceImpl(
            final AuthenticationService authenticationService,
            final ConfigService<? extends HodSsoConfig> configService
    ) throws HodErrorException {
        this.authenticationService = authenticationService;
        this.configService = configService;
    }

    private TokenAndUuid authenticate() throws HodErrorException {
        final ApiKey apiKey = configService.getConfig().getApiKey();

        TokenAndUuid tokenAndUuid = cache.get();

        if (!isTokenValid(tokenAndUuid)) {
            synchronized (lock) {
                tokenAndUuid = cache.get();

                // Check that the token is valid again because another thread might have updated it
                if (!isTokenValid(tokenAndUuid)) {
                    final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> unboundToken = authenticationService.authenticateUnbound(apiKey, TokenType.HmacSha1.INSTANCE);

                    final UUID uuid;

                    if (tokenAndUuid == null) {
                        final UnboundTokenInformation information = authenticationService.getHmacUnboundTokenInformation(unboundToken);
                        uuid = information.getAuthentication().getUuid();
                    } else {
                        uuid = tokenAndUuid.uuid;
                    }

                    tokenAndUuid = new TokenAndUuid(unboundToken, uuid);
                    cache.set(tokenAndUuid);
                }
            }
        }

        return tokenAndUuid;
    }

    @Override
    public AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> getUnboundToken() throws HodErrorException {
        return authenticate().token;
    }

    @Override
    public UUID getAuthenticationUuid() throws HodErrorException {
        return authenticate().uuid;
    }

    private boolean isTokenValid(final TokenAndUuid tokenAndUuid) {
        return tokenAndUuid != null && tokenAndUuid.token.getExpiry().minus(EXPIRY_TOLERANCE).isAfterNow();
    }

    @Data
    private static class TokenAndUuid {
        private final AuthenticationToken<EntityType.Unbound, TokenType.HmacSha1> token;
        private final UUID uuid;
    }
}
