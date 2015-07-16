/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.SignedRequest;
import com.hp.autonomy.hod.client.error.HodErrorException;

/**
 * Service for producing signed requests which can be sent to HP Haven OnDemand SSO to authenticate
 */
public interface HodAuthenticationRequestService {

    /**
     * Generates a signed list applications request
     * @return A signed request which when sent to HP Haven OnDemand will return a list of applications
     * @throws HodErrorException If an error occurs communicating with HP Haven OnDemand
     */
    SignedRequest getListApplicationRequest() throws HodErrorException;

    /**
     * Generates a signed combined token request
     * @param domain The HP Haven OnDemand domain to authenticate against
     * @param application The HP Haven OnDemand domain to authenticate against
     * @param userStoreDomain The HP Haven OnDemand user store domain to authenticate against
     * @param userStoreName The HP Haven OnDemand user store to authenticate against
     * @return A signed request which when sent to HP Haven OnDemand will return a combined token
     * @throws HodErrorException If an error occurs communicating with HP Haven OnDemand
     */
    SignedRequest getCombinedRequest(String domain, String application, String userStoreDomain, String userStoreName) throws HodErrorException;

}
