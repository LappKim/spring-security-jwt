package com.slowstarter.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.slowstarter.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long>
{
    boolean existsByUsername(String username);

    UserEntity findByUsername(String username);
}
