package com.berk2s.authorizationserver.web;


import com.berk2s.authorizationserver.AuthorizationServerApplication;
import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.UserRepository;
import lombok.Getter;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.transaction.Transactional;
import java.util.UUID;

@SpringBootTest
@ContextConfiguration
@AutoConfigureMockMvc
public abstract class IntegrationTest {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;


    @Transactional
    public User getUser() {
        User user = new User();
        user.setUsername(RandomStringUtils.random(12));
        user.setEmail(RandomStringUtils.random(5));
        user.setPhoneNumber(RandomStringUtils.random(5));
        user.setPassword(passwordEncoder.encode("password"));
        user.setAccountNonExpired(true);
        user.setEnabled(true);
        user.setCredentialsNonExpired(true);
        user.setAccountNonLocked(true);

        userRepository.save(user);

        return user;
    }

}
