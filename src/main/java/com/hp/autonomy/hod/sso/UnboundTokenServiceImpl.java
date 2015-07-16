/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.frontend.abc.beanconfiguration.HostedCondition;
import com.hp.autonomy.frontend.abc.configuration.AbcHostedConfig;
import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.hod.client.api.authentication.ApiKey;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationService;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.error.HodErrorException;
import org.joda.time.ReadablePeriod;
import org.joda.time.Seconds;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.stereotype.Service;

import java.util.concurrent.atomic.AtomicReference;

@Service
@Conditional(HostedCondition.class)
public class UnboundTokenServiceImpl implements UnboundTokenService {
    // Time before token expiry before we fetch a new token
    static final ReadablePeriod EXPIRY_TOLERANCE = Seconds.seconds(10);

    private final AtomicReference<AuthenticationToken> unboundTokenCache = new AtomicReference<>(null);
    private final Object lock = new Object();

    @Autowired
    private ConfigService<AbcHostedConfig> configService;

    @Autowired
    private AuthenticationService authenticationService;

    @Override
    public AuthenticationToken getUnboundToken() throws HodErrorException {
        AuthenticationToken unboundToken = unboundTokenCache.get();

        if (isTokenValid(unboundToken)) {
            return unboundToken;
        } else {
            synchronized (lock) {
                unboundToken = unboundTokenCache.get();

                // Check that the token is valid again because another thread might have updated it
                if (isTokenValid(unboundToken)) {
                    return unboundToken;
                } else {
                    unboundToken = authenticationService.authenticateUnbound(getApiKey());

                    unboundTokenCache.set(unboundToken);

                    return unboundToken;
                }
            }
        }
    }

    private boolean isTokenValid(final AuthenticationToken unboundToken) {
        return unboundToken != null && unboundToken.getExpiry().minus(EXPIRY_TOLERANCE).isAfterNow();
    }

    private ApiKey getApiKey() {
        return new ApiKey(configService.getConfig().getHod().getApiKey());
    }
}
