package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.services.RevocationService;
import com.berk2s.authorizationserver.web.models.RevocationRequestDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RequiredArgsConstructor
@RequestMapping(RevocationController.ENDPOINT)
@RestController
public class RevocationController {

    public static final String ENDPOINT = "/revoke";

    private final RevocationService revocationService;
    private final ObjectMapper objectMapper;

    @PostMapping(consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public void revokeToken(@RequestHeader(name = "Authorization", required = true) String authorizationHeader,
                            @RequestParam Map<String, String> requestParam) {
        revocationService.revokeToken(authorizationHeader,
                objectMapper.convertValue(requestParam, RevocationRequestDto.class));
    }

}
