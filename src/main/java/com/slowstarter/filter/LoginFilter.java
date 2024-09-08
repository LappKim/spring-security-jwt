package com.slowstarter.filter;

import java.util.Collection;
import java.util.Iterator;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.slowstarter.component.JwtComponent;
import com.slowstarter.dto.CustomUserDetails;
import com.slowstarter.service.RefreshTokenService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtComponent jwtComponent;
    private final RefreshTokenService refreshTokenService;
    public LoginFilter(AuthenticationManager authenticationManager, JwtComponent jwtComponent, RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.jwtComponent = jwtComponent;
        this.refreshTokenService = refreshTokenService;
    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        //클라이언트 요청에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        log.trace("username = [{}]", username);
        log.trace("password = [{}]", password);

        //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

        //token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(token);
    }

    //로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authentication) {
        log.trace("authentication.getName() = [{}]", authentication.getName());

        CustomUserDetails customUserDetails = (CustomUserDetails)authentication.getPrincipal();

        log.trace("customUserDetails        = [{}]", customUserDetails);

        String username = customUserDetails.getUsername();
        String role     = null;

        log.trace("username                 = [{}]", username);
        log.trace("1 role                   = [{}]", role);

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();

        if(iterator.hasNext() == true) {
            GrantedAuthority auth = iterator.next();
            role = auth.getAuthority();
        }

        log.trace("2 role                   = [{}]", role);

        // 36000 / 1000 -> 36초?
        // 10분 10분 * 60초 * 1000 밀리초 = 600000
        String accessToken  = this.jwtComponent.createJwtAccess(username, role);
        // 24시간 24시간 * 60분 * 60초 * 1000 밀리초 = 86400000
        String refreshToken = this.jwtComponent.createJwtRefresh(username, role);

        log.trace("accessToken               = [{}]", accessToken);
        log.trace("refreshToken              = [{}]", refreshToken);

        //Refresh 토큰 저장
        this.refreshTokenService.saveRefreshToken(username, refreshToken);

        /**
         * access token은 header (localStorge) 저장
         * refresh token은 cookie에 저장
         */
        response.setHeader(this.jwtComponent.getKeyAccess(), accessToken);
        response.addCookie(this.jwtComponent.createCookie(refreshToken));
        response.setStatus(HttpStatus.OK.value());
    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        log.trace("unsuccessful");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
