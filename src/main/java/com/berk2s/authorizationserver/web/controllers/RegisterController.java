package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.security.RegisterService;
import com.berk2s.authorizationserver.web.models.RegisterRequestDto;
import com.berk2s.authorizationserver.web.models.RegisterResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(originPatterns = "*", allowCredentials = "true", allowedHeaders = "*")
@RequiredArgsConstructor
@RequestMapping(RegisterController.ENDPOINT)
@Controller
public class RegisterController {

    public static final String ENDPOINT = "/register";

    private final RegisterService registerService;

    @GetMapping
    public String getRegister() {
        return "register";
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public void postRegister(@RequestBody RegisterRequestDto registerRequest) {
        registerService.register(registerRequest);
    }

}
