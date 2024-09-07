package com.slowstarter.service;

import javax.security.auth.login.LoginException;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.slowstarter.dto.JoinDto;
import com.slowstarter.entity.UserEntity;
import com.slowstarter.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class JoinService
{
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder)
    {
        super();
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(JoinDto joinDto) throws Exception
    {
        /**
         * DB에 회원 유무 확인.
         */
        boolean exist = userRepository.existsByUsername(joinDto.getUsername());
        if(exist == true)
        {
            throw new LoginException("이미 등록된 사용자입니다.");
        }

        UserEntity user = new UserEntity();

        user.setUsername(joinDto.getUsername());
        user.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));
        user.setRole(joinDto.getRole());

        log.trace("UserEntity -> [{}]", user);

        userRepository.save(user);

        return;
    }
}
