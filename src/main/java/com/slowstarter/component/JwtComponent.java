package com.slowstarter.component;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtComponent {
    private static final String JWT_USERNAME                   = "username";
    private static final String JWT_ROLE                       = "role";
    private static final String JWT_CATEGORY                   = "category";
    private static final String JWT_ACCESS                     = "access";
    private static final String JWT_REFRESH                    = "refresh";
    private static final int    JWT_ACCESS_EXPIRED_MILISECOND  = 1800000;  // 30분
    private static final int    JWT_REFRESH_EXPIRED_MILISECOND = 86400000; // 24시간

    private SecretKey secretKey;

    public JwtComponent(@Value("${spring.jwt.secret}") String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }
    private Claims getPayload(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
    }
    public String getUsername(String token) {
        return getPayload(token).get(getKeyUsername(), String.class);
    }
    public String getRole(String token) {
        return getPayload(token).get(getKeyRole(), String.class);
    }
    public String getCategory(String token) {
        return getPayload(token).get(getKeyCategory(), String.class);
    }
    public boolean isExpired(String token) {
        return getPayload(token).getExpiration().before(new Date());
    }
    public String createJwtAccess(String username, String role) {
        return createJwtImpl(getKeyAccess(), username, role, (long)getAccessExpired());
    }
    public String createJwtRefresh(String username, String role) {
        return createJwtImpl(getKeyRefresh(), username, role, (long)getRefreshExpired());
    }
    private String createJwtImpl(String category, String username, String role, Long expiredMs) {
        Date issuedAt   = new Date(System.currentTimeMillis());
        Date expiration = new Date(System.currentTimeMillis() + expiredMs);

        log.trace("issuedAt   => [{}]", issuedAt);
        log.trace("expiration => [{}]", expiration);

        return Jwts.builder()
                .claim(getKeyCategory(), category)
                .claim(getKeyUsername(), username)
                .claim(getKeyRole(), role)
                .issuedAt(issuedAt)
                .expiration(expiration)
                .signWith(secretKey)
                .compact();
    }
    public Cookie createCookie(String refreshToken) {
        int maxAge = getRefreshExpired()/1000; // milisecond를 second로 변환
        Cookie cookie = new Cookie(getKeyRefresh(), refreshToken);
        cookie.setMaxAge(maxAge);
        // cookie.setSecure(true); //https 사용시
        // cookie.setPath("/");    //cookie 동작 위치!
        cookie.setHttpOnly(true);
        return cookie;
    }
    public Cookie removeCookie() {
        Cookie cookie = new Cookie(getKeyRefresh(), null);
        cookie.setMaxAge(0);
        // cookie.setSecure(true); //https 사용시
        // cookie.setPath("/");    //cookie 동작 위치!
        cookie.setHttpOnly(true);
        return cookie;
    }
    public String getRefreshToken(Cookie[] cookies) {
        for(Cookie cookie : cookies) {
            if(getKeyRefresh().equals(cookie.getName()) == true) {
                return cookie.getValue();
            }
        }
        return null;
    }
    public String getKeyUsername() {
        return JWT_USERNAME;
    }
    public String getKeyRole() {
        return JWT_ROLE;
    }
    public String getKeyCategory() {
        return JWT_CATEGORY;
    }
    public String getKeyAccess() {
        return JWT_ACCESS;
    }
    public String getKeyRefresh() {
        return JWT_REFRESH;
    }
    public int getAccessExpired() {
        return JWT_ACCESS_EXPIRED_MILISECOND;
    }
    public int getRefreshExpired() {
        return JWT_REFRESH_EXPIRED_MILISECOND;
    }
}
