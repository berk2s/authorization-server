package com.berk2s.authorizationserver.bootstrap;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.domain.user.Authority;
import com.berk2s.authorizationserver.domain.user.Role;
import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.AuthorityRepository;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.repository.RoleRepository;
import com.berk2s.authorizationserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

@Slf4j
@Profile("local")
@RequiredArgsConstructor
@Component
public class DataLoader implements CommandLineRunner {

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;
    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        loadClients();
    }

    private void loadClients() throws URISyntaxException {


        User user = new User();
        user.setUsername("username");
        user.setPassword(passwordEncoder.encode("password"));
        user.setLastName("lastname");
        user.setFirstName("firstname");
        user.setPhoneNumber("phone");
        user.setEmail("email");
        user.setAccountNonLocked(true);
        user.setEnabled(true);
        user.setAccountNonExpired(true);
        user.setCredentialsNonExpired(true);


        userRepository.save(user);

        Authority authority = new Authority();
        authority.setAuthorityName("WRITE_BASKET");
        authority.addUsers(user);

        Authority authority2 = new Authority();
        authority2.setAuthorityName("READ_BASKET");
        authority2.addUsers(user);

        Role role = new Role();
        role.setRoleName("USER");
        role.addUser(user);

        authorityRepository.saveAll(Set.of(authority, authority2));
        roleRepository.save(role);

        log.info("\n\n\n\n Created User Id: "
            + user.getId().toString()
            + "\n\n\n\n");
        log.info("\n\n\n\n Created Role Size: "
            + user.getRoles().size()
            + "\n\n\n\n");
        log.info("\n\n\n\n Created Authority Size: "
            + user.getAuthorities().size()
            + "\n\n\n\n");

        Client client = new Client();
        client.setClientId("clientId");
        client.setClientSecret(passwordEncoder.encode(""));
        client.setConfidential(false);
        client.setRedirectUris(Set.of(new URI("http://localhost:4200"), new URI("http://redirect-uri")));
        client.setGrantTypes(Set.of(GrantType.AUTHORIZATION_CODE,
                GrantType.PASSWORD,
                GrantType.REFRESH_TOKEN,
                GrantType.CLIENT_CREDENTIALS,
                GrantType.TOKEN_EXCHANGE));

        Client client2 = new Client();
        client2.setClientId("clientWithoutCode");
        client2.setConfidential(false);
        client2.setRedirectUris(Set.of(new URI("http://redirect-uri")));
        client2.setGrantTypes(Set.of(GrantType.PASSWORD,
                GrantType.REFRESH_TOKEN,
                GrantType.CLIENT_CREDENTIALS,
                GrantType.TOKEN_EXCHANGE));

        Client client3 = new Client();
        client3.setClientId("clientWithSecret");
        client3.setClientSecret(passwordEncoder.encode("clientSecret"));
        client3.setConfidential(true);
        client3.setRedirectUris(Set.of(new URI("http://redirect-uri")));
        client3.setGrantTypes(Set.of(GrantType.AUTHORIZATION_CODE,
                GrantType.PASSWORD,
                GrantType.REFRESH_TOKEN,
                GrantType.CLIENT_CREDENTIALS,
                GrantType.TOKEN_EXCHANGE));


        Client client4 = new Client();
        client4.setClientId("clientWithoutClientCredentials");
        client3.setClientSecret(passwordEncoder.encode("clientSecret"));
        client4.setConfidential(true);
        client4.setRedirectUris(Set.of(new URI("http://redirect-uri")));
        client4.setGrantTypes(Set.of(GrantType.PASSWORD,
                GrantType.REFRESH_TOKEN,
                GrantType.AUTHORIZATION_CODE,
                GrantType.TOKEN_EXCHANGE));

        Client client5 = new Client();
        client5.setClientId("clientWithoutPassword");
        client5.setClientSecret(passwordEncoder.encode("clientSecret"));
        client5.setConfidential(true);
        client5.setRedirectUris(Set.of(new URI("http://redirect-uri")));
        client5.setGrantTypes(Set.of(GrantType.CLIENT_CREDENTIALS,
                GrantType.REFRESH_TOKEN,
                GrantType.AUTHORIZATION_CODE,
                GrantType.TOKEN_EXCHANGE));

        Client client6 = new Client();
        client6.setClientId("clientWithoutRefreshToken");
        client6.setConfidential(false);
        client6.setRedirectUris(Set.of(new URI("http://redirect-uri")));
        client6.setGrantTypes(Set.of(GrantType.CLIENT_CREDENTIALS,
                GrantType.PASSWORD,
                GrantType.AUTHORIZATION_CODE,
                GrantType.TOKEN_EXCHANGE));

        clientRepository.saveAll(Set.of(client, client2, client3, client4, client5, client6));
    }
}
