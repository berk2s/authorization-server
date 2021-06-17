package com.berk2s.authorizationserver.bootstrap;

import com.berk2s.authorizationserver.config.ServerConfiguration;
import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.domain.oauth.GrantType;
import com.berk2s.authorizationserver.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

@Profile("local")
@RequiredArgsConstructor
@Component
public class DataLoader implements CommandLineRunner {

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        loadClients();
    }

    private void loadClients() throws URISyntaxException {
        Client client = new Client();
        client.setClientId("clientId");
        client.setConfidential(false);
        client.setRedirectUris(Set.of(new URI("http://redirect-uri")));
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
        client4.setClientSecret("clientSecret");
        client4.setConfidential(true);
        client4.setRedirectUris(Set.of(new URI("http://redirect-uri")));
        client4.setGrantTypes(Set.of(GrantType.PASSWORD,
                GrantType.REFRESH_TOKEN,
                GrantType.AUTHORIZATION_CODE,
                GrantType.TOKEN_EXCHANGE));

        clientRepository.saveAll(Set.of(client, client2, client3, client4));
    }
}
