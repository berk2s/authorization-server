package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.domain.oauth.AuthorizationCode;
import com.berk2s.authorizationserver.repository.AuthorizationCodeRepository;
import com.berk2s.authorizationserver.services.impl.AuthorizationCodeServiceImpl;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.exceptions.InvalidRequestException;
import com.berk2s.authorizationserver.web.mappers.AuthorizationCodeMapper;
import com.berk2s.authorizationserver.web.models.AuthorizationCodeDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mapstruct.factory.Mappers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationCodeServiceTest {

    @Mock
    AuthorizationCodeRepository authorizationCodeRepository;

    @Spy
    private final AuthorizationCodeMapper authorizationCodeMapper = Mappers.getMapper(AuthorizationCodeMapper.class);

    @InjectMocks
    AuthorizationCodeServiceImpl authorizationCodeService;

    AuthorizationCode authorizationCode;
    AuthorizationCodeDto authorizationCodeDto;

    @BeforeEach
    void setUp() throws URISyntaxException {
        authorizationCode = AuthorizationCode.builder()
                .code("code")
                .clientId("clientId")
                .scopes("scope1 scope2")
                .subject("subject")
                .redirectUri("http://redirect-uri")
                .nonce("nonce")
                .codeChallenge("codeChallenge")
                .codeChallengeMethod("codeChallengeMethod")
                .build();

        authorizationCodeDto =
                authorizationCodeMapper.authorizationCodeToAuthorizationDto(authorizationCode);
    }

    @DisplayName("Get Authorization Code Successfully")
    @Test
    void getAuthorizationCodeSuccessfully() {
        when(authorizationCodeRepository.findByCode(any())).thenReturn(Optional.of(authorizationCode));

        AuthorizationCodeDto returnedAuthorizationCodeDto =
                authorizationCodeService.getAuthorizationCode(authorizationCode.getCode(), authorizationCode.getClientId());

        assertThat(returnedAuthorizationCodeDto.getCode())
                .isEqualTo(authorizationCodeDto.getCode());

        verify(authorizationCodeRepository, times(1)).findByCode(any());
    }

    @DisplayName("Create Authorization Code Succesfully")
    @Test
    void createAuthorizationCodeSuccessfully() throws URISyntaxException {
        AuthorizationCodeDto authorizationCodeDto =
                authorizationCodeService.createAuthorizationCode("clientId",
                        new URI("http://redirect-uri"),
                        Set.of("scope"),
                        "subject",
                        "nonce",
                        "codeChallenge",
                        "codeChallengeMethod");

        assertThat(authorizationCodeDto.getClientId())
                .isEqualTo("clientId");

        assertThat(authorizationCodeDto.getRedirectUri())
                .isEqualTo(new URI("http://redirect-uri"));

        assertThat(authorizationCodeDto.getScopes())
                .isEqualTo(Set.of("scope"));

        assertThat(authorizationCodeDto.getNonce())
                .isEqualTo("nonce");

        assertThat(authorizationCodeDto.getCodeChallenge())
                .isEqualTo("codeChallenge");

        assertThat(authorizationCodeDto.getCodeChallengeMethod())
                .isEqualTo("codeChallengeMethod");

        assertThat(authorizationCodeDto.getCode())
                .isNotNull();

        verify(authorizationCodeRepository, times(1)).save(any());
    }

    @DisplayName("Delete Authorization Code Successfully")
    @Test
    void deleteAuthorizationCodeSuccessfully() {
        doNothing().when(authorizationCodeRepository).deleteByCode(any());

        authorizationCodeService.deleteAuthorizationCode("code");

        verify(authorizationCodeRepository, times(1)).deleteByCode(any());
    }

    @DisplayName("Test Exceptions")
    @Nested
    class AuthorizationCodeExceptions {

        @DisplayName("Invalid Code Throws Exceptions")
        @Test
        void shouldInvalidCodeThrowsException() {
            AuthorizationCodeDto returnedCodeDto = null;
            try {
                returnedCodeDto = authorizationCodeService.getAuthorizationCode("code", "clientId");
            } catch (InvalidRequestException e) {
                assertThat(e.getMessage())
                        .isEqualTo(ErrorDesc.NULL_CODE.getDesc());
            } finally {
                 if(returnedCodeDto != null) {
                     fail("Catch block didn't work");
                 }

                 verify(authorizationCodeRepository, times(1)).findByCode(any());
            }
        }

        @DisplayName("Expired Code Throws Exception")
        @Test
        void shouldExpiredCodeThrowsException() {
            authorizationCode.setExpiry(LocalDateTime.now().minusMinutes(10));
            AuthorizationCodeDto returnedCodeDto = null;
            try {
                when(authorizationCodeRepository.findByCode(any())).thenReturn(Optional.of(authorizationCode));

                returnedCodeDto =
                        authorizationCodeService.getAuthorizationCode(authorizationCode.getCode(), authorizationCode.getClientId());

            } catch (InvalidRequestException e) {
                assertThat(e.getMessage())
                        .isEqualTo(ErrorDesc.EXPIRED_CODE.getDesc());
            } finally {
                if (returnedCodeDto != null) {
                    fail("Catch block didn't worked");
                }

                verify(authorizationCodeRepository, times(1)).findByCode(any());
            }
        }

        @DisplayName("Unmatched Code Throws Exception")
        @Test
        void shouldUnmatchedCodeThrowsExpcetion() {

            AuthorizationCodeDto returnedCodeDto = null;
            try {
                when(authorizationCodeRepository.findByCode(any())).thenReturn(Optional.of(authorizationCode));

                returnedCodeDto =
                        authorizationCodeService.getAuthorizationCode(authorizationCode.getCode(), "invalidClientId");

            } catch (InvalidRequestException e) {
                assertThat(e.getMessage())
                        .isEqualTo(ErrorDesc.INVALID_CODE.getDesc());
            } finally {
                if (returnedCodeDto != null) {
                    fail("Catch block didn't worked");
                }

                verify(authorizationCodeRepository, times(1)).findByCode(any());
            }
        }

    }

}