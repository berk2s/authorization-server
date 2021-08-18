package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class SecurityUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public SecurityUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("Cannot find User [username: {}]", username);
                    throw new UsernameNotFoundException(ErrorDesc.INVALID_USER.getDesc());
                });

        return new SecurityUserDetails(user);
    }
}
