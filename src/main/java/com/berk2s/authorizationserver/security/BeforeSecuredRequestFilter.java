package com.berk2s.authorizationserver.security;

import com.berk2s.authorizationserver.web.controllers.AuthorizationController;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@Slf4j
@Component
public class BeforeSecuredRequestFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {

        if(httpServletRequest.getCookies() != null) {

            for (Cookie cookie : httpServletRequest.getCookies()) {
                log.info("name: {}, value: {}, domain: {}", cookie.getName(), cookie.getValue(), cookie.getDomain());
            }
        } else {
            log.info("Cookies are null");
        }


        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return AuthorizationController.ENDPOINT.equals(request.getRequestURI());
    }
}
