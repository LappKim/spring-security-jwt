package com.slowstarter.filter;

import java.io.IOException;

import org.springframework.http.HttpMethod;
import org.springframework.web.filter.GenericFilterBean;

import com.slowstarter.component.JwtComponent;
import com.slowstarter.service.RefreshTokenService;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomLogoutFilter extends GenericFilterBean {
    private final JwtComponent jwtComponent;
    private final RefreshTokenService refreshTokenService;
    public CustomLogoutFilter(JwtComponent jwtComponent, RefreshTokenService refreshTokenService) {
        super();
        this.jwtComponent = jwtComponent;
        this.refreshTokenService = refreshTokenService;
    }
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        doFilterImpl((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }
    private void doFilterImpl(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        log.trace("CustomLogoutFilter(GenericFilterBean) start!!!!!!");
        //path and method verify
        String requestUri = request.getRequestURI();
        log.trace("requestUri [{}]", requestUri);
        if (requestUri.matches("^\\/logout$") == false) {
            log.trace("logout 아님");
            chain.doFilter(request, response);
            return;
        }

        String httpMethod = request.getMethod();
        log.error("httpMethod [{}]", httpMethod);

        if(HttpMethod.POST.matches(request.getMethod()) == false) {
            log.trace("Http method가 POST 아님");
            chain.doFilter(request, response);
            return;
        }

        //get refresh token
        String refreshToken = this.jwtComponent.getRefreshToken(request.getCookies());

        log.trace("refreshToken [{}]", refreshToken);

        //refresh null check
        if(refreshToken == null) {
            log.error("refresh token null");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //expired check
        try {
            boolean isRefreshTokenExpired = this.jwtComponent.isExpired(refreshToken);
            log.trace("isRefreshTokenExpired [{}]", isRefreshTokenExpired);

        } catch (ExpiredJwtException e) {
            log.error("refresh token expired");
            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // DB에 저장되어 있는지 확인
        boolean isRefreshTokenExistDB = this.refreshTokenService.existsByRefreshToken(refreshToken);
        log.trace("isRefreshTokenExistDB [{}]", isRefreshTokenExistDB);
        if(isRefreshTokenExistDB == false) {
            log.error("refresh token does not exists on database");
            //response body
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String refresh  = this.jwtComponent.getKeyRefresh();
        String category = this.jwtComponent.getCategory(refreshToken);

        if (refresh.equals(category) == false) {
            log.error("invalid refresh token category = [{}]", category);
            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //로그아웃 진행
        //Refresh 토큰 DB에서 제거
        this.refreshTokenService.deleteByRefreshToken(refreshToken);

        //Refresh 토큰 Cookie 값 0
        response.addCookie(this.jwtComponent.removeCookie());
        response.setStatus(HttpServletResponse.SC_OK);
    }
}
