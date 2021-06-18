package com.berk2s.authorizationserver.web;

import com.berk2s.authorizationserver.services.DiscoveryService;
import com.berk2s.authorizationserver.web.models.DiscoveryDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RequestMapping(DiscoveryController.ENDPOINT)
@RestController
public class DiscoveryController {

    public static final String ENDPOINT = "/.well-known/openid-configuration";

    private final DiscoveryService discoveryService;

    @GetMapping
    public ResponseEntity<DiscoveryDto> getDiscovery() {
        return new ResponseEntity<>(discoveryService.getDiscovery(), HttpStatus.OK);
    }

}
