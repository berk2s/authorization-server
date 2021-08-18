package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.services.IntrospectionService;
import com.berk2s.authorizationserver.web.models.IntrospectionRequestDto;
import com.berk2s.authorizationserver.web.models.IntrospectionResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@CrossOrigin(originPatterns = "*", allowCredentials = "true", allowedHeaders = "*")
@RequiredArgsConstructor
@RequestMapping(IntrospectionController.ENDPOINT)
@RestController
public class IntrospectionController {

    public static final String ENDPOINT = "/token_info";

    private final IntrospectionService introspectionService;
    private final ObjectMapper objectMapper;

    @PostMapping(consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<IntrospectionResponseDto> getTokenInfo(@RequestHeader(name = "Authorization", required = true) String header,
                                                                 @RequestParam Map<String, String> requestParams) {
        return new ResponseEntity<IntrospectionResponseDto>(introspectionService
                .getTokenInfo(header, objectMapper.convertValue(requestParams, IntrospectionRequestDto.class)), HttpStatus.OK);
    }
}
