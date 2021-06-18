package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.services.AuthorizationCodeTokenService;
import com.berk2s.authorizationserver.services.ClientCredentialsTokenService;
import com.berk2s.authorizationserver.services.PasswordCodeTokenService;
import com.berk2s.authorizationserver.services.RefreshTokenCodeService;
import com.berk2s.authorizationserver.web.models.token.TokenRequestDto;
import com.berk2s.authorizationserver.web.models.token.TokenResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RequiredArgsConstructor
@RequestMapping(TokenController.ENDPOINT)
@RestController
public class TokenController {

    public static final String ENDPOINT = "/token";

    private final ObjectMapper objectMapper;
    private final AuthorizationCodeTokenService authorizationCodeTokenService;
    private final ClientCredentialsTokenService clientCredentialsTokenService;
    private final PasswordCodeTokenService passwordCodeTokenService;
    private final RefreshTokenCodeService refreshTokenCodeService;

    @PostMapping(consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<TokenResponseDto> getToken(@RequestHeader(name = "Authorization", required = false) String authorizationHeader,
                                                     @RequestParam Map<String, String> params) {

        TokenRequestDto tokenRequest = objectMapper.convertValue(params, TokenRequestDto.class);

        if (tokenRequest.getGrantType().equalsIgnoreCase(GrantType.AUTHORIZATION_CODE.getGrant())) {
            return new ResponseEntity<>(authorizationCodeTokenService.getToken(authorizationHeader, tokenRequest), HttpStatus.OK);
        } else if(tokenRequest.getGrantType().equalsIgnoreCase(GrantType.CLIENT_CREDENTIALS.getGrant())) {
            return new ResponseEntity<>(clientCredentialsTokenService.getToken(authorizationHeader, tokenRequest), HttpStatus.OK);
        } else if(tokenRequest.getGrantType().equalsIgnoreCase(GrantType.PASSWORD.getGrant())) {
            return new ResponseEntity<>(passwordCodeTokenService.getToken(authorizationHeader, tokenRequest), HttpStatus.OK);
        } else if(tokenRequest.getGrantType().equalsIgnoreCase(GrantType.REFRESH_TOKEN.getGrant())) {
            return new ResponseEntity<>(refreshTokenCodeService.getToken(authorizationHeader, tokenRequest), HttpStatus.OK);
        } else {
            throw new RuntimeException("Unknown grant type");
        }
    }

}
