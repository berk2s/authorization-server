package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.web.models.AuthorizeRequestParamDto;

import java.net.URI;
import java.net.URISyntaxException;

public interface AuthorizationService {

    URI authorizeRequest(AuthorizeRequestParamDto authorizeRequestDto, SecurityUserDetails securityUserDetails) throws URISyntaxException;

}
