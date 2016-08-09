/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationService;
import com.hp.autonomy.hod.client.api.authentication.SignedRequest;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.error.HodErrorException;

import java.net.URL;
import java.util.Collection;
import java.util.Collections;

/**
 * Default implementation of HodAuthenticationRequestService
 */
public class HodAuthenticationRequestServiceImpl implements HodAuthenticationRequestService {

    private final ConfigService<? extends HodSsoConfig> configService;

    private final AuthenticationService authenticationService;

    private final UnboundTokenService<TokenType.HmacSha1> unboundTokenService;

    /**
     * Creates a new HodAuthenticationRequestServiceImpl
     * @param configService The configuration service which will provide the configuration
     * @param authenticationService The authentication service to use to sign the requests
     * @param unboundTokenService The unbound token service used to provide teh unbound token
     */
    public HodAuthenticationRequestServiceImpl(
        final ConfigService<? extends HodSsoConfig> configService,
        final AuthenticationService authenticationService,
        final UnboundTokenService<TokenType.HmacSha1> unboundTokenService
    ) {
        this.configService = configService;
        this.authenticationService = authenticationService;
        this.unboundTokenService = unboundTokenService;
    }

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
            TokenType.Simple.INSTANCE,
            true
        );
    }

    @Override
    public SignedRequest getCombinedPatchRequest(final URL redirectUrl) throws HodErrorException, InvalidOriginException {
        final String redirectOrigin = resolveOrigin(redirectUrl);

        if (getAllowedOrigins().contains(redirectOrigin)) {
            final URL ssoUrl = configService.getConfig().getSsoUrl();

            return authenticationService.combinedPatchRequest(
                    Collections.singleton(resolveOrigin(ssoUrl)),
                    redirectUrl.toString(),
                    unboundTokenService.getUnboundToken()
            );
        } else {
            throw new InvalidOriginException(redirectUrl);
        }
    }

    private Collection<String> getAllowedOrigins() {
        return configService.getConfig().getAllowedOrigins();
    }

    private String resolveOrigin(final URL url) {
        return url.getProtocol() + "://" + url.getAuthority();
    }
}
