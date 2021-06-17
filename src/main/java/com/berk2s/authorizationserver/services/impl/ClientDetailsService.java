package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.oauth.Client;
import com.berk2s.authorizationserver.repository.ClientRepository;
import com.berk2s.authorizationserver.security.SecurityClientDetails;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class ClientDetailsService implements UserDetailsService {

    private final ClientRepository clientRepository;

    @Override
    public SecurityClientDetails loadUserByUsername(String clientId) throws UsernameNotFoundException {
        Client client = clientRepository
                .findByClientId(clientId)
                .orElseThrow(() -> {
                    log.warn("Cannot find Client [client: {}]", clientId);
                    throw new UsernameNotFoundException(ErrorDesc.INVALID_CLIENT.getDesc());
                });

        return new SecurityClientDetails(client);
    }
}
