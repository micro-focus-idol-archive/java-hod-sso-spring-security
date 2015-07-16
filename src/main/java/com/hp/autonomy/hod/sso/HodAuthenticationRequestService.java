/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.SignedRequest;
import com.hp.autonomy.hod.client.error.HodErrorException;

public interface HodAuthenticationRequestService {

    SignedRequest getListApplicationRequest() throws HodErrorException;

    SignedRequest getCombinedRequest(String domain, String application, String userStoreDomain, String userStoreName) throws HodErrorException;

}
