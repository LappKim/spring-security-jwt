package com.slowstarter.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.slowstarter.entity.RefreshTokenEntity;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {
    boolean existsByRefreshToken(String refreshToken);
    void deleteByRefreshToken(String refreshToken);
}
