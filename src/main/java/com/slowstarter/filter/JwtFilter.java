package com.slowstarter.filter;

import java.io.IOException;
import java.io.PrintWriter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.slowstarter.component.JwtComponent;
import com.slowstarter.dto.CustomUserDetails;
import com.slowstarter.entity.UserEntity;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtFilter extends OncePerRequestFilter {
    private final JwtComponent jwtComponent;

    public JwtFilter(JwtComponent jwtComponent) {
        this.jwtComponent = jwtComponent;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.trace("JwtFilter(OncePerRequestFilter) start!!!!!!");


        String access = this.jwtComponent.getKeyAccess();
        //request에서 access 헤더를 찾음
        String accessToken = request.getHeader(access);

        //access 헤더 검증
        if(accessToken == null) {
            log.error("accessToken null");
            filterChain.doFilter(request, response);

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
        // if(jwtComponent.isExpired(accessToken) == true) {
        //     log.error("access token expired");
        //     PrintWriter writer = response.getWriter();
        //     writer.print("access token expired");
        //
        //     //response status code
        //     response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        //     return;
        // }
        try {
            boolean isExpired = jwtComponent.isExpired(accessToken);

            log.trace("isExpired => [{}]", isExpired);
        } catch(ExpiredJwtException e) {
            log.error("access token expired");
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 토큰이 access인지 확인 (발급시 페이로드에 명시)
        String category = jwtComponent.getCategory(accessToken);
        log.trace("category => [{}]", category);
        if(access.equals(category) == false) {
            log.error("invalid access token");

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        //토큰에서 username과 role 획득
        String username = jwtComponent.getUsername(accessToken);
        String role     = jwtComponent.getRole(accessToken);

            //userEntity를 생성하여 값 set
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);

        // UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(
                customUserDetails,
                null,
                customUserDetails.getAuthorities()
                );
        // 세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
