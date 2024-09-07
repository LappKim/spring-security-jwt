package com.slowstarter.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.slowstarter.dto.CustomUserDetails;
import com.slowstarter.entity.UserEntity;
import com.slowstarter.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class CustomUserDetailsService implements UserDetailsService
{
    private final UserRepository userRepository;
    public CustomUserDetailsService(UserRepository userRepository)
    {
        super();
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        UserEntity userEntity = userRepository.findByUsername(username);

        log.trace("UserEntity -> [{}]", userEntity);

        if(userEntity != null)
        {
            return new CustomUserDetails(userEntity);
        }

        return null;
    }
}
