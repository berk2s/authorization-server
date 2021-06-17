package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.oauth.AuthorizationCode;
import com.berk2s.authorizationserver.repository.AuthorizationCodeRepository;
import com.berk2s.authorizationserver.services.AuthorizationCodeService;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.exceptions.InvalidRequestException;
import com.berk2s.authorizationserver.web.exceptions.ServerException;
import com.berk2s.authorizationserver.web.mappers.AuthorizationCodeMapper;
import com.berk2s.authorizationserver.web.models.AuthorizationCodeDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthorizationCodeServiceImpl implements AuthorizationCodeService {

    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final AuthorizationCodeMapper authorizationCodeMapper;

    @Override
    public AuthorizationCodeDto getAuthorizationCode(String code, String clientId) {
        try {
            AuthorizationCode authorizationCode = authorizationCodeRepository
                    .findByCode(code)
                    .orElseThrow(() -> {
                        log.warn("Invalid authorization code [clientId: {}, code: {}]", clientId, code);
                        throw new InvalidRequestException(ErrorDesc.NULL_CODE.getDesc());
                    });

            if (authorizationCode.isExpired()) {
                log.warn("The given authorization code has been expired [clientId: {}, code: {}]", clientId, code);
                deleteAuthorizationCode(code);
                throw new InvalidRequestException(ErrorDesc.EXPIRED_CODE.getDesc());
            } else if (!authorizationCode.getClientId().equals(clientId)) {
                log.warn("The given client id and code is not matched [clientId: {}, code: {}]", clientId, code);
                throw new InvalidRequestException(ErrorDesc.INVALID_CODE.getDesc());
            }

            return authorizationCodeMapper.authorizationCodeToAuthorizationDto(authorizationCode);
        } catch (URISyntaxException e) {
            log.warn(e.getMessage() + "[clientId: {}]", clientId);
            throw new ServerException("Bad redirect uri");
        }
    }

    @Override
    public AuthorizationCodeDto createAuthorizationCode(String clientId, URI redirectUri, Set<String> scopes, String subject, String nonce, String codeChallenge, String codeChallengeMethod) {
        String code = RandomStringUtils.random(32, true, true);

        AuthorizationCodeDto authorizationCodeDto = AuthorizationCodeDto.builder()
                .code(code)
                .clientId(clientId)
                .scopes(scopes)
                .subject(subject)
                .redirectUri(redirectUri)
                .nonce(nonce)
                .codeChallenge(codeChallenge)
                .codeChallengeMethod(codeChallengeMethod)
                .build();

        authorizationCodeRepository.save(authorizationCodeMapper.authorizationCodeDtoToAuthorizationCode(authorizationCodeDto));

        return authorizationCodeDto;
    }

    @Override
    public void deleteAuthorizationCode(String code) {
        authorizationCodeRepository.deleteByCode(code);
    }
}
