package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.config.JwtPkiConfiguration;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.impl.JWTServiceImpl;
import com.berk2s.authorizationserver.web.models.token.JWTCommand;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.util.IdGenerator;
import org.springframework.util.JdkIdGenerator;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JWTServiceTest {

    @Mock
    private JwtPkiConfiguration jwtPkiConfiguration;

    @Spy
    private final IdGenerator idGenerator = new JdkIdGenerator();


    @InjectMocks
    JWTServiceImpl jwtService;

    User user;
    UUID userId;

    RSAKey rsaKey;
    JWSSigner jwsSigner;

    JWTCommand jwtCommand;

    @BeforeEach
    void setUp() throws JOSEException {
        userId = UUID.randomUUID();

        user = new User();
        user.setId(userId);
        user.setUsername("username");

        rsaKey = new RSAKeyGenerator(2048).keyID("1").generate();
        jwsSigner = new RSASSASigner(rsaKey);

        Map<String, Object> claims = new HashMap<>();
        claims.put("authorities", Set.of("authoritiy1", "authority2"));

        jwtCommand = JWTCommand.builder()
                .userDetails(new SecurityUserDetails(user))
                .clientId("clientId")
                .scopes(Set.of("openid"))
                .audiences(Set.of("aud1", "aud2"))
                .nonce("nonce")
                .expiryDateTime(LocalDateTime.now().plusMinutes(10))
                .claims(claims)
                .build();


    }


    @DisplayName("Should Create Jwt Successfully")
    @Test
    void testShouldCreateJwtSuccessfully() throws ParseException, JOSEException {
        when(jwtPkiConfiguration.getPublicKey()).thenReturn(rsaKey.toPublicJWK());
        when(jwtPkiConfiguration.getJwsSigner()).thenReturn(jwsSigner);

        String signedJwtSerialize = jwtService.createJWT(jwtCommand);

        SignedJWT signedJWT = SignedJWT.parse(signedJwtSerialize);
        JWSVerifier jwsVerifier = new RSASSAVerifier(rsaKey.toPublicJWK());

        assertThat(signedJWT.verify(jwsVerifier))
                .isEqualTo(true);

        verify(jwtPkiConfiguration, times(1)).getPublicKey();
        verify(jwtPkiConfiguration, times(1)).getJwsSigner();
    }

    @DisplayName("Test Validate Token")
    @Test
    void shouldTestParseAndValidateToken() throws JOSEException, ParseException {
        when(jwtPkiConfiguration.getPublicKey()).thenReturn(rsaKey.toPublicJWK());
        when(jwtPkiConfiguration.getJwsSigner()).thenReturn(jwsSigner);
        when(jwtPkiConfiguration.getJwsVerifier()).thenReturn(new RSASSAVerifier(rsaKey.toPublicJWK()));

        String signedJwtSerialize = jwtService.createJWT(jwtCommand);

        JWTClaimsSet claimsSet = jwtService.parseAndValidate(signedJwtSerialize);

        assertThat(claimsSet.getSubject())
                .isEqualTo(user.getId().toString());

        verify(jwtPkiConfiguration, times(1)).getJwsVerifier();
        verify(jwtPkiConfiguration, times(1)).getPublicKey();
        verify(jwtPkiConfiguration, times(1)).getJwsSigner();
    }


    @DisplayName("Test SignedJwt")
    @Test
    void shouldTestSignedJwtReturnsSuccessfully() throws ParseException, JOSEException {

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getId().toString())
                .issuer("wtPki.getIssuer()")
                .audience(Arrays.asList("aud1", "aud2"))
                .issueTime(new Date())
                .notBeforeTime(new Date())
                .expirationTime(Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant()))
                .jwtID(idGenerator.generateId().toString())
                .claim("nonce", "nonce")
                .build();

        when(jwtPkiConfiguration.getPublicKey()).thenReturn(new RSAKeyGenerator(2048).keyID("1").generate());

        SignedJWT signedJWT = jwtService.signJwt(jwtClaimsSet);

        assertThat(signedJWT.getJWTClaimsSet())
                .isEqualTo(jwtClaimsSet);

        verify(jwtPkiConfiguration, times(1)).getPublicKey();
    }


}