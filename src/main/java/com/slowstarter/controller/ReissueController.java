package com.slowstarter.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.slowstarter.component.JwtComponent;
import com.slowstarter.service.RefreshTokenService;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class ReissueController {
    private final JwtComponent jwtComponent;
    private final RefreshTokenService refreshTokenService;

    public ReissueController(JwtComponent jwtComponent, RefreshTokenService refreshTokenService) {
        this.jwtComponent = jwtComponent;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
        String refresh = this.jwtComponent.getKeyRefresh();
        //get refresh token
        String refreshToken = this.jwtComponent.getRefreshToken(request.getCookies());

        log.trace("refreshToken [{}]", refreshToken);

        if(refreshToken == null) {
            log.error("refresh token null");
            //response status code
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
        // if(this.jwtComponent.isExpired(refreshToken) == true) {
        //     log.error("refresh token expired");
        //     return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        // }
        //expired check
        try {
            boolean isRefreshTokenExpired = this.jwtComponent.isExpired(refreshToken);
            log.trace("isRefreshTokenExpired [{}]", isRefreshTokenExpired);

        } catch (ExpiredJwtException e) {
            log.error("refresh token expired");
            //response status code
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        // DB에 저장되어 있는지 확인
        boolean isRefreshTokenExistDB = this.refreshTokenService.existsByRefreshToken(refreshToken);
        log.trace("isRefreshTokenExistDB [{}]", isRefreshTokenExistDB);
        if(isRefreshTokenExistDB == false) {
            log.error("refresh token does not exists on database");
            //response body
            return new ResponseEntity<>("refresh token does not exists on database", HttpStatus.BAD_REQUEST);
        }
        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = this.jwtComponent.getCategory(refreshToken);
        log.trace("category [{}]", category);
        if (refresh.equals(category) == false) {
            log.error("invalid refresh token");
            //response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        String username = this.jwtComponent.getUsername(refreshToken);
        String role     = this.jwtComponent.getRole(refreshToken);

        //make new JWT
        String newAccessToken  = this.jwtComponent.createJwtAccess(username, role);
        // 24시간 24시간 * 60분 * 60초 * 1000 밀리초 = 86400000
        String newRefreshToken = this.jwtComponent.createJwtRefresh(username, role);

        // 기존 refreshToken 삭제
        this.refreshTokenService.deleteByRefreshToken(refreshToken);
        //Refresh 토큰 저장
        this.refreshTokenService.saveRefreshToken(username, newRefreshToken);

        //response
        response.setHeader(this.jwtComponent.getKeyAccess(), newAccessToken);
        response.addCookie(this.jwtComponent.createCookie(newRefreshToken));

        return new ResponseEntity<>(HttpStatus.OK);
    }
}
