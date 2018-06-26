/*
 * Copyright 2015-2018 Micro Focus International plc.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.error.HodErrorException;

import java.util.UUID;

/**
 * Service for retrieving an unbound authentication token from Micro Focus Haven OnDemand
 * @param <T> The type of unbound token returned by this service
 */
public interface UnboundTokenService<T extends TokenType> {

    /**
     * @return An unbound token from Micro Focus Haven OnDemand
     * @throws HodErrorException If a problem occurs
     */
    AuthenticationToken<EntityType.Unbound, T> getUnboundToken() throws HodErrorException;

    /**
     * @return The UUID of the authentication used to generate unbound tokens
     * @throws HodErrorException If a problem occurs
     */
    UUID getAuthenticationUuid() throws HodErrorException;

}
