package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.services.AuthorizationService;
import com.berk2s.authorizationserver.web.models.AuthorizeRequestParamDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.net.URISyntaxException;
import java.util.Map;

@CrossOrigin(originPatterns = "*", allowCredentials = "true", allowedHeaders = "*")
@RequiredArgsConstructor
@RequestMapping(AuthorizationController.ENDPOINT)
@RestController
public class AuthorizationController {

    public static final String ENDPOINT = "/authorize";

    private final AuthorizationService authorizationService;
    private final ObjectMapper objectMapper;

    @GetMapping
    public ResponseEntity authorizeRequest(@AuthenticationPrincipal SecurityUserDetails securityUserDetails,
                                           @RequestParam Map<String, String> params) throws URISyntaxException {
        return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY)
                .location(authorizationService.authorizeRequest(objectMapper.convertValue(params, AuthorizeRequestParamDto.class), securityUserDetails))
                .build();
    }

}
