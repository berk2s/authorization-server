package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.services.PKCEService;
import com.berk2s.authorizationserver.utils.ChallengeMethod;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.exceptions.CodeChallengeException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Slf4j
@RequiredArgsConstructor
@Service
public class PKCEServiceImpl implements PKCEService {

    @Override
    public void verifyCodeChallenge(String challengeMethod, String codeVerifier, String codeChallenge) {
        if (StringUtils.isBlank(codeVerifier)) {
            log.warn("The code_verifier is missing");
            throw new CodeChallengeException(ErrorDesc.MISSING_CODE_VERIFIER.getDesc());
        }

        if (codeVerifier.length() < 43 || codeVerifier.length() > 128) {
            log.warn("Insufficient code_verifier");
            throw new CodeChallengeException(ErrorDesc.INVALID_CODE_VERIFIER.getDesc());
        }

        if (ChallengeMethod.S256.name().equalsIgnoreCase(challengeMethod)) {
            String hashedCodeVerifier = hashCodeVerifier(codeVerifier);

            if (!MessageDigest.isEqual(codeChallenge.getBytes(StandardCharsets.UTF_8), hashedCodeVerifier.getBytes(StandardCharsets.UTF_8))) {
                log.warn("code_challenge and code_verifier is not matched");
                throw new CodeChallengeException(ErrorDesc.INVALID_CODE_CHALLENGE.getDesc());
            }
        } else if (codeChallenge == null || challengeMethod.isBlank() || ChallengeMethod.PLAIN.name().equalsIgnoreCase(challengeMethod)) {
            if (!codeChallenge.equals(codeVerifier)) {
                log.warn("challenge_method and code_verifier is not matching where method is plain");
                throw new CodeChallengeException(ErrorDesc.INVALID_CODE_CHALLENGE.getDesc());
            }
        } else {
            log.warn("Unknown challenge_method");
            throw new CodeChallengeException(ErrorDesc.INVALID_CHALLENGE_METHOD.getDesc());
        }
    }

    @Override
    public String hashCodeVerifier(String codeVerifier) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = messageDigest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));

            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException ex) {
            log.warn("No such algorithm. Reason: {}", ex.getMessage());
            throw new CodeChallengeException(ErrorDesc.NO_SUCH_ALGORITHIM.getDesc());
        }
    }

}
