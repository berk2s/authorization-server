package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.config.JwtPkiConfiguration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@CrossOrigin(originPatterns = "*", allowCredentials = "true", allowedHeaders = "*")
@RequiredArgsConstructor
@RequestMapping(JWKSetController.ENDPOINT)
@RestController
public class JWKSetController {

    public static final String ENDPOINT = "/jwks";

    private final JwtPkiConfiguration jwtPkiConfiguration;

    @GetMapping
    private Map<String, Object> getJwkSet() {
        log.info("JWK Set is created");
        return jwtPkiConfiguration.getJwkSet().toJSONObject();
    }

}
