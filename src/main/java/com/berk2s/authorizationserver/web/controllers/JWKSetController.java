package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.config.JwtPkiConfiguration;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RequiredArgsConstructor
@RequestMapping(JWKSetController.ENDPOINT)
@RestController
public class JWKSetController {

    public static final String ENDPOINT = "/jwks";

    private final JwtPkiConfiguration jwtPkiConfiguration;

    @GetMapping
    private Map<String, Object> getJwkSet() {
        return jwtPkiConfiguration.getJwkSet().toJSONObject();
    }

}
