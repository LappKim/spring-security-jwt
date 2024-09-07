package com.slowstarter.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.slowstarter.dto.JoinDto;
import com.slowstarter.service.JoinService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class JoinController
{
    private final JoinService joinService;

    public JoinController(JoinService joinService)
    {
        this.joinService = joinService;
    }
    @PostMapping(value = "/join")
    public String joinProcess(JoinDto joinDto) throws Exception {
        log.trace("joinDto -> [{}]", joinDto);
        joinService.joinProcess(joinDto);
        return "ok";
    }
}
