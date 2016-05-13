package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.tokeninformation.UserInformation;

/**
 * Interface for fetching a security info string given a user
 */
public interface SecurityInfoRetriever {

    /**
     * Fetch the security info string from a user
     * @param userInfo The user's info to use for fetching a security info string
     * @return A security info string for the provided user
     */
    String getSecurityInfo(UserInformation userInfo);
}
