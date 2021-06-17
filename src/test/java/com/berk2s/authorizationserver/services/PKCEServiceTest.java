package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.services.impl.PKCEServiceImpl;
import com.berk2s.authorizationserver.utils.ChallengeMethod;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.exceptions.CodeChallengeException;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;


@ExtendWith(MockitoExtension.class)
public class PKCEServiceTest {

    @InjectMocks
    PKCEServiceImpl pkceService;

    String codeVerifier;
    String codeChallenge;

    @BeforeEach
    void setUp() {
        codeVerifier = RandomStringUtils.random(50);
        codeChallenge = generateEncodedSHA256(codeVerifier);
    }

    @DisplayName("Test Should Code Verifier Returns Successfully")
    @Test
    void shouldCodeVerifierReturnsSuccessfully() {
        boolean isOkey = true;
        try {
            pkceService.verifyCodeChallenge(ChallengeMethod.S256.name(), codeVerifier, codeChallenge);
            isOkey = false;
        }  finally {
            if(isOkey) {
                fail("Catch block didn't work");
            }
        }
    }

    @DisplayName("Test Should Hash Code Verifier Returns Successfully")
    @Test
    void shouldHashCodeVerifierReturnsSuccessfully() {
        String returnedHashedCode = pkceService.hashCodeVerifier(codeVerifier);

        assertThat(returnedHashedCode)
                .isEqualTo(codeChallenge);
    }

    @DisplayName("Test PKCE Exceptions")
    @Nested
    class TestPKCEExceptions {

        @DisplayName("Test Missing Code Verifier Throws Exception")
        @Test
        void missingCodeVerifierThrowsException() {
            boolean isOkey = true;
            try {
                pkceService.verifyCodeChallenge("challengeMethod", null, "codeChallenge");
                isOkey = false;
            } catch (CodeChallengeException ex) {
                assertThat(ex.getMessage())
                        .isEqualTo(ErrorDesc.MISSING_CODE_VERIFIER.getDesc());
            } finally {
                if(!isOkey) {
                    fail("Catch block didn't work");
                }
            }
        }

        @DisplayName("Test Invalid Code Verifier Throws Exception")
        @Test
        void invalidCodeVerifierThrowsException() {
            boolean isOkey = true;
            try {
                pkceService.verifyCodeChallenge("challengeMethod", "invalid code verifier", "codeChallenge");
                isOkey = false;
            } catch (CodeChallengeException ex) {
                assertThat(ex.getMessage())
                        .isEqualTo(ErrorDesc.INVALID_CODE_VERIFIER.getDesc());
            } finally {
                if(!isOkey) {
                    fail("Catch block didn't work");
                }
            }
        }

        @DisplayName("Test Unmatched Code Verifier and Code Challenge Throws Exception")
        @Test
        void unmatchedCodeVerifierAndCodeChallengeThrowsExpcetion() {
            boolean isOkey = true;
            try {
                pkceService.verifyCodeChallenge(ChallengeMethod.S256.name(), RandomStringUtils.random(45), "codeChallenge");
                isOkey = false;
            } catch (CodeChallengeException ex) {
                assertThat(ex.getMessage())
                        .isEqualTo(ErrorDesc.INVALID_CODE_CHALLENGE.getDesc());
            } finally {
                if(!isOkey) {
                    fail("Catch block didn't work");
                }
            }
        }

        @DisplayName("Test Plain Code Verifier Throws Exception")
        @Test
        void plainCodeVerifierThrowsException() {
            boolean isOkey = true;
            try {
                pkceService.verifyCodeChallenge(ChallengeMethod.PLAIN.name(), codeVerifier, "invalidChallenge");
                isOkey = false;
            } catch (CodeChallengeException ex) {
                assertThat(ex.getMessage())
                        .isEqualTo(ErrorDesc.INVALID_CODE_CHALLENGE.getDesc());
            } finally {
                if(!isOkey) {
                    fail("Catch block didn't work");
                }
            }
        }

        @DisplayName("Test Invalid Code Challenge Method Throws Exception")
        @Test
        void invalidCodeChallengeMethodThrowsException() {
            boolean isOkey = true;
            try {
                pkceService.verifyCodeChallenge("invalid_method", codeVerifier, "invalidChallenge");
                isOkey = false;
            } catch (CodeChallengeException ex) {
                assertThat(ex.getMessage())
                        .isEqualTo(ErrorDesc.INVALID_CHALLENGE_METHOD.getDesc());
            } finally {
                if(!isOkey) {
                    fail("Catch block didn't work");
                }
            }
        }
    }

    private String generateEncodedSHA256(String codeVerifier) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = messageDigest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));

            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException ex) {
            throw new CodeChallengeException(ErrorDesc.NO_SUCH_ALGORITHIM.getDesc());
        }
    }

}
