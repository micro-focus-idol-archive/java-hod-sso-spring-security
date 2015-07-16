/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.frontend.abc.beanconfiguration.HostedCondition;
import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationService;
import com.hp.autonomy.hod.client.api.authentication.SignedRequest;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.error.HodErrorException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@Conditional(HostedCondition.class)
public class HodAuthenticationRequestServiceImpl implements HodAuthenticationRequestService {
    @Autowired
    private ConfigService<? extends HodSsoConfig> configService;

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private UnboundTokenService unboundTokenService;

    @Override
    public SignedRequest getListApplicationRequest() throws HodErrorException {
        return authenticationService.combinedGetRequest(getAllowedOrigins(), unboundTokenService.getUnboundToken());
    }

    @Override
    public SignedRequest getCombinedRequest(
            final String domain,
            final String application,
            final String userStoreDomain,
            final String userStoreName
    ) throws HodErrorException {
        return authenticationService.combinedRequest(
                getAllowedOrigins(),
                unboundTokenService.getUnboundToken(),
                domain,
                application,
                userStoreDomain,
                userStoreName,
                TokenType.simple,
                true
        );
    }

    private Set<String> getAllowedOrigins() {
        return configService.getConfig().getAllowedOrigins();
    }
}
