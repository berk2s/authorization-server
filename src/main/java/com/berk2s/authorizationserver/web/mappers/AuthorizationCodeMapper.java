package com.berk2s.authorizationserver.web.mappers;

import com.berk2s.authorizationserver.domain.oauth.AuthorizationCode;
import com.berk2s.authorizationserver.web.models.AuthorizationCodeDto;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashSet;

@Mapper(imports = {URI.class, Arrays.class, HashSet.class})
public interface AuthorizationCodeMapper {


    @Mappings({
            @Mapping(target = "scopes", expression = "java( String.join(\" \", authorizationCodeDto.getScopes()) )"),
            @Mapping(target = "redirectUri", expression = "java( authorizationCodeDto.getRedirectUri().toString() )")
    })
    AuthorizationCode authorizationCodeDtoToAuthorizationCode(AuthorizationCodeDto authorizationCodeDto);

    @Mappings({
            @Mapping(target = "scopes", expression = "java( new HashSet<>(Arrays.asList(authorizationCode.getScopes().split(\" \"))) )"),
            @Mapping(target = "redirectUri", expression = "java( new URI(authorizationCode.getRedirectUri()) )")
    })
    AuthorizationCodeDto authorizationCodeToAuthorizationDto(AuthorizationCode authorizationCode) throws URISyntaxException;

}
