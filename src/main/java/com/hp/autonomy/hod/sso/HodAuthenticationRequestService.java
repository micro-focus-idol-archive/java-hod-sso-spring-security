/*
 * Copyright 2015-2018 Micro Focus International plc.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.SignedRequest;
import com.hp.autonomy.hod.client.error.HodErrorException;

import java.net.URL;

/**
 * Service for producing signed requests which can be sent to Micro Focus Haven OnDemand SSO to authenticate
 */
public interface HodAuthenticationRequestService {

    /**
     * Generate a signed authenticate combined PATCH request. This can be used in the browser to create a combined SSO token.
     * @return A signed request to make from the user's browser
     * @throws HodErrorException If an error occurs authenticating with Micro Focus Haven OnDemand
     */
    SignedRequest getCombinedPatchRequest() throws HodErrorException;

    /**
     * Generate a signed authenticate combined PATCH request to be sent from the SSO page.
     * @param redirectUrl Redirect URL for the PATCH request; must be in the allowed origins
     * @return A signed request for generating a combined SSO token
     * @throws HodErrorException If an error occurs communicating with Micro Focus Haven OnDemand
     * @throws InvalidOriginException If the redirect URL is not in the allowed origins
     */
    SignedRequest getSsoPageCombinedPatchRequest(URL redirectUrl) throws HodErrorException, InvalidOriginException;

    /**
     * Generates a signed list applications request
     * @deprecated Use the cookie-less SSO process instead
     * @return A signed request which when sent to Micro Focus Haven OnDemand will return a list of applications
     * @throws HodErrorException If an error occurs communicating with Micro Focus Haven OnDemand
     */
    @Deprecated
    SignedRequest getListApplicationRequest() throws HodErrorException;

    /**
     * Generates a signed combined token request
     * @deprecated Use the cookie-less SSO process instead
     * @param domain The Micro Focus Haven OnDemand domain to authenticate against
     * @param application The Micro Focus Haven OnDemand domain to authenticate against
     * @param userStoreDomain The Micro Focus Haven OnDemand user store domain to authenticate against
     * @param userStoreName The Micro Focus Haven OnDemand user store to authenticate against
     * @return A signed request which when sent to Micro Focus Haven OnDemand will return a combined token
     * @throws HodErrorException If an error occurs communicating with Micro Focus Haven OnDemand
     */
    @Deprecated
    SignedRequest getCombinedRequest(String domain, String application, String userStoreDomain, String userStoreName) throws HodErrorException;

}
