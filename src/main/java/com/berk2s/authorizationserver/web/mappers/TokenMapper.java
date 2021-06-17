package com.berk2s.authorizationserver.web.mappers;

import com.berk2s.authorizationserver.domain.token.RefreshToken;
import com.berk2s.authorizationserver.web.models.token.RefreshTokenDto;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;

import java.util.UUID;

@Mapper(imports = UUID.class)
public interface TokenMapper {

    @Mappings({
            @Mapping(target = "subject", expression = "java( refreshToken.getSubject().toString() )")
    })
    RefreshTokenDto refreshTokenToRefreshTokenDto(RefreshToken refreshToken);

    @Mappings({
            @Mapping(target = "subject", expression = "java( UUID.fromString(refreshTokenDto.getSubject()) )")
    })
    RefreshToken refreshTokenDtoToRefreshToken(RefreshTokenDto refreshTokenDto);

}
