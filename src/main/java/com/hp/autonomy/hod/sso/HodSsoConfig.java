/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.ApiKey;

import java.util.Set;

/**
 * A configuration object which provides the necessary information to authenticate with HP Haven OnDemand SSO
 */
public interface HodSsoConfig {

    /**
     * @return The application API key to use for authentication
     */
    ApiKey getApiKey();

    /**
     * @return The origins from which the signed request can be sent
     */
    Set<String> getAllowedOrigins();

}
