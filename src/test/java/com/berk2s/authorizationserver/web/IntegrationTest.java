package com.berk2s.authorizationserver.web;


import com.berk2s.authorizationserver.AuthorizationServerApplication;
import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.user.Authority;
import com.berk2s.authorizationserver.domain.user.Role;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.AuthorityRepository;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.RoleRepository;
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
import java.util.Locale;
import java.util.UUID;

@SpringBootTest
@ContextConfiguration
@AutoConfigureMockMvc
public abstract class IntegrationTest {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;

    @Autowired
    ClientRepository clientRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    AuthorityRepository authorityRepository;

    @Transactional
    public User getUser() {
        Role role = new Role();
        role.setRoleName(RandomStringUtils.random(6, true, false).toUpperCase(Locale.ROOT));

        Role role2 = new Role();
        role2.setRoleName(RandomStringUtils.random(6, true, false).toUpperCase(Locale.ROOT));

        Authority authority = new Authority();
        authority.setAuthorityName(RandomStringUtils.random(6, true, false).toUpperCase(Locale.ROOT));

        User user = new User();
        user.setUsername(RandomStringUtils.random(6, true, false).toUpperCase(Locale.ROOT));
        user.setPassword(passwordEncoder.encode("password"));
        user.setFirstName("firstname");
        user.setLastName("lastname");
        user.setEmail(RandomStringUtils.random(5));
        user.setPhoneNumber(RandomStringUtils.random(5));
        user.setAccountNonExpired(true);
        user.setEnabled(true);
        user.setCredentialsNonExpired(true);
        user.setAccountNonLocked(true);

        role.addUser(user);
        role2.addUser(user);
        authority.addUsers(user);

        userRepository.save(user);
        roleRepository.save(role);
        roleRepository.save(role2);
        authorityRepository.save(authority);
        return user;
    }

    public Client getClient() {
        return clientRepository.findByClientId("clientId")
                .orElseThrow(() -> new RuntimeException("err"));
    }

}
