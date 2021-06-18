package com.berk2s.authorizationserver.web.controllers;

import com.berk2s.authorizationserver.services.UserInfoService;
import com.berk2s.authorizationserver.web.models.UserInfoDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RequestMapping(UserInfoController.ENDPOINT)
@RestController
public class UserInfoController {

    public static final String ENDPOINT = "/userinfo";

    private final UserInfoService userInfoService;

    @GetMapping
    public ResponseEntity<UserInfoDto> getUserInfo(@RequestHeader(name = "Authorization", required = true) String authorizationHeader) {
        return new ResponseEntity<>(userInfoService.getUserInfo(authorizationHeader), HttpStatus.OK);
    }

}


