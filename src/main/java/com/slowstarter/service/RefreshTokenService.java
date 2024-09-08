package com.slowstarter.service;

import java.util.Date;

import org.springframework.stereotype.Service;

import com.slowstarter.component.JwtComponent;
import com.slowstarter.entity.RefreshTokenEntity;
import com.slowstarter.repository.RefreshTokenRepository;

@Service
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtComponent jwtComponent;
    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JwtComponent jwtComponent) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtComponent = jwtComponent;
    }
    public void saveRefreshToken(String username, String refreshToken) {
        int expiredMs = this.jwtComponent.getRefreshExpired();
        RefreshTokenEntity refreshTokenEntity = new RefreshTokenEntity();
        refreshTokenEntity.setUsername(username);
        refreshTokenEntity.setRefreshToken(refreshToken);
        refreshTokenEntity.setExpiration(new Date(System.currentTimeMillis() + expiredMs).toString());
        this.refreshTokenRepository.save(refreshTokenEntity);
    }
    public void deleteByRefreshToken(String refreshToken) {
        this.refreshTokenRepository.deleteByRefreshToken(refreshToken);
    }
    public boolean existsByRefreshToken(String refreshToken) {
        return this.refreshTokenRepository.existsByRefreshToken(refreshToken);
    }
}
