package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.services.LoginService;
import com.berk2s.authorizationserver.web.models.LoginRequestDto;
import com.berk2s.authorizationserver.web.models.LoginResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RequestMapping(LoginController.ENDPOINT)
@Controller
public class LoginController {

    public static final String ENDPOINT = "/sign-in";

    private final LoginService loginService;

    @GetMapping
    public String signIn() {
        return "login";
    }


}
