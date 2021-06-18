package com.berk2s.authorizationserver.utils;

import com.berk2s.authorizationserver.web.exceptions.InvalidClientException;
import com.berk2s.authorizationserver.web.models.ClientCredentialsDto;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.token.TokenRequestDto;
import com.berk2s.authorizationserver.web.models.token.TokenType;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
public final class AuthenticationParser {


    public static String encodeBase64(String clientId, String clientSecret) {
        byte[] plainCredentials = (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8);
        String encodedCredentials = Base64.getEncoder().encodeToString(plainCredentials);
        return AuthorizationType.BASIC.getTypeWithBlank() + encodedCredentials;
    }

    public static ClientCredentialsDto basicParser(String header) {
        try {
            header = header.trim();

            byte[] base64Token = header.substring(AuthorizationType.BASIC.getTypeWithBlank().length())
                    .getBytes(StandardCharsets.UTF_8);
            byte[] decoded = Base64.getDecoder().decode(base64Token);

            String token = new String(decoded, StandardCharsets.UTF_8);

            int grater = token.indexOf(":");

            if (grater == -1) {
                log.warn("Cannot parse basic authentication header [token: {}]", header);
                throw new BadCredentialsException(ErrorDesc.BAD_CREDENTIALS.getDesc());
            }

            String clientId = token.substring(0, grater);
            String clientSecret = token.substring(grater + 1);

            if (clientId.isBlank()) {
                log.warn("Cannot parse authentication header. The reason is that there is no client id.");
                throw new BadCredentialsException(ErrorDesc.BAD_CREDENTIALS.getDesc());
            }

            return ClientCredentialsDto.builder()
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .build();
        } catch (IllegalArgumentException ex) {
            log.warn("Cannot parse authentication header. Reason: {}", ex.getMessage());
            throw new BadCredentialsException(ErrorDesc.BAD_CREDENTIALS.getDesc());
        }
    }

    public static ClientCredentialsDto parseAndValidate(String header, TokenRequestDto tokenRequest) {
        if (StringUtils.isNotBlank(header)) {
            ClientCredentialsDto clientCredentials = basicParser(header);

            if (!clientCredentials.getClientId().equals(tokenRequest.getClientId())
                    || !clientCredentials.getClientSecret().equals(tokenRequest.getClientSecret())) {
                log.warn("Basic credentials and params credentials are not matching");
                throw new InvalidClientException(ErrorDesc.INVALID_CLIENT.getDesc());
            }

            return clientCredentials;
        }

        return ClientCredentialsDto.builder()
                .clientId(tokenRequest.getClientId())
                .clientSecret(tokenRequest.getClientSecret())
                .build();
    }

    public static String bearerParser(String authorizationHeader) {
        if (authorizationHeader == null || !StringUtils.startsWithIgnoreCase(authorizationHeader.trim(), TokenType.BEARER.name())) {
            log.warn("Invalid bearer token [Authentication Token: {}]", authorizationHeader);
            throw new BadCredentialsException(ErrorDesc.BAD_CREDENTIALS.getDesc());
        }

        return authorizationHeader.substring(7);
    }
}
