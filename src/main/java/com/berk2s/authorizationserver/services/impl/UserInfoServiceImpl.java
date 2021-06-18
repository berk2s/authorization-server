package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.services.JWTService;
import com.berk2s.authorizationserver.services.UserInfoService;
import com.berk2s.authorizationserver.utils.AuthenticationParser;
import com.berk2s.authorizationserver.web.exceptions.InvalidGrantException;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.UserInfoDto;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserInfoServiceImpl implements UserInfoService {

    private final JWTService jwtService;
    private final UserRepository userRepository;

    @Override
    public UserInfoDto getUserInfo(String authorizationHeader) {
        String token = AuthenticationParser.bearerParser(authorizationHeader);

        JWTClaimsSet jwtClaimsSet = jwtService.parseAndValidate(token);

        UUID userId = UUID.fromString(jwtClaimsSet.getSubject());

        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("Cannot find user by given id [userId: {}]", userId);
                    throw new InvalidGrantException(ErrorDesc.INVALID_TOKEN_SUBJECT.getDesc());
                });

        return UserInfoDto.builder()
                .sub(user.getId().toString())
                .name(user.getFirstName() + " " + user.getLastName())
                .nickname(user.getUsername())
                .profile(user.getUsername())
                .roles(user.getRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toSet()))
                .authorities(user.getAuthorities().stream().map(a -> a.getAuthorityName()).collect(Collectors.toSet()))
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .preferredUsername(user.getUsername())
                .build();
    }
}
