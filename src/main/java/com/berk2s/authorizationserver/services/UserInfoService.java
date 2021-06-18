package com.berk2s.authorizationserver.services;

import com.berk2s.authorizationserver.web.models.UserInfoDto;

public interface UserInfoService {

    UserInfoDto getUserInfo(String authorizationHeader);

}
