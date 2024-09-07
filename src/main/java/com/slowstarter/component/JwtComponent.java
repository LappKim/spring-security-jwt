package com.slowstarter.component;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtComponent {
    private SecretKey secretKey;

    public JwtComponent(@Value("${spring.jwt.secret}")String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    private Claims getPayload(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
    }
    public String getUsername(String token) {
        return getPayload(token).get("username", String.class);
    }

    public String getRole(String token) {
        return getPayload(token).get("role", String.class);
    }

    public boolean isExpired(String token) {
        return getPayload(token).getExpiration().before(new Date());
    }

    public String createJwt(String username, String role, Long expiredMs) {
        Date issuedDate = new Date(System.currentTimeMillis());
        Date expiration = new Date(System.currentTimeMillis() + expiredMs);

        log.trace("issuedDate => [{}]", issuedDate);
        log.trace("expiration => [{}]", expiration);

        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(issuedDate)
                .expiration(expiration)
                .signWith(secretKey)
                .compact();
    }
}
