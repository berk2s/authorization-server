package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.config.JwtPkiConfiguration;
import com.berk2s.authorizationserver.services.DiscoveryService;
import com.berk2s.authorizationserver.web.controllers.*;
import com.berk2s.authorizationserver.web.models.DiscoveryDto;
import com.berk2s.authorizationserver.web.models.Scope;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class DiscoveryServiceImpl implements DiscoveryService {

    private final JwtPkiConfiguration jwtPkiConfiguration;

    @Override
    public DiscoveryDto getDiscovery() {
        DiscoveryDto discoveryDto = new DiscoveryDto();

        String issuer = jwtPkiConfiguration.getIssuer();

        discoveryDto.setIssuer(issuer);

        discoveryDto.setAuthorizationEndpoint(issuer + AuthorizationController.ENDPOINT); // TODO: AuthorizationController
        discoveryDto.setTokenEndpoint(issuer + TokenController.ENDPOINT); // TODO: TokenController
        discoveryDto.setIntrospectionEndpoint(issuer + IntrospectionController.ENDPOINT); // TODO: IntrospectionController
        discoveryDto.setUserinfoEndpoint(issuer + UserInfoController.ENDPOINT); // TODO: UserInfoController
        discoveryDto.setRevocationEndpoint(issuer + RevocationController.ENDPOINT); // TODO
        discoveryDto.setRegistrationEndpoint(issuer); // TODO

        discoveryDto.setJwksUri(issuer + JWKSetController.ENDPOINT);

        discoveryDto.getGrantTypesSupported().add(""); // TODO: GrandType

        discoveryDto.getResponseModesSupported().add("code");

        discoveryDto.getScopesSupported().add(Scope.OPENID.name().toLowerCase());
        discoveryDto.getScopesSupported().add(Scope.OFFLINE_ACCESS.name().toLowerCase());
        discoveryDto.getScopesSupported().add(Scope.PROFILE.name().toLowerCase());
        discoveryDto.getScopesSupported().add(Scope.EMAIL.name().toLowerCase());
        discoveryDto.getScopesSupported().add(Scope.PHONE.name().toLowerCase());
        discoveryDto.getScopesSupported().add(Scope.ADDRESS.name().toLowerCase());

        discoveryDto.getResponseModesSupported().add("query");
        discoveryDto.getResponseModesSupported().add("form_post");

        discoveryDto.getSubjectTypesSupported().add("public");

        discoveryDto.getIdTokenSigningAlgValuesSupported().add("RS256");

        discoveryDto.getTokenEndpointAuthMethodsSupported().add("client_secret_basic");
        discoveryDto.getTokenEndpointAuthMethodsSupported().add("client_secret_post");

        discoveryDto.getCodeChallengeMethodsSupported().add("S256");
        discoveryDto.getCodeChallengeMethodsSupported().add("plain");

        discoveryDto.getClaimsSupported().add("aud");
        discoveryDto.getClaimsSupported().add("exp");
        discoveryDto.getClaimsSupported().add("iss");
        discoveryDto.getClaimsSupported().add("iat");
        discoveryDto.getClaimsSupported().add("sub");
        discoveryDto.getClaimsSupported().add("email"); // TODO: enhance claims
        discoveryDto.getClaimsSupported().add("username"); // TODO: enhance claims

        discoveryDto.getTokenEndpointAuthSigningAlgValuesSupported().add("RS256");

        return discoveryDto;
    }
}
