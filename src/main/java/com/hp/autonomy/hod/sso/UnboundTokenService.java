/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.error.HodErrorException;

/**
 * Service for retrieving an unbound authentication token from HP Haven OnDemand
 */
public interface UnboundTokenService {

    /**
     * @return An unbound token from HP Haven OnDemand
     * @throws HodErrorException
     */
    AuthenticationToken getUnboundToken() throws HodErrorException;

}
