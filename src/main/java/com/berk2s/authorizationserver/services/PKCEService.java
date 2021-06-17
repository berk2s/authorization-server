package com.berk2s.authorizationserver.services;

import java.security.NoSuchAlgorithmException;

public interface PKCEService {

    void verifyCodeChallenge(String challengeMethod,
                             String codeVerifier,
                             String codeChallenge);

    String hashCodeVerifier(String codeVerifier) throws NoSuchAlgorithmException;

}
