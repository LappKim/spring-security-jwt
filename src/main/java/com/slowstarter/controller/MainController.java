package com.slowstarter.controller;

import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class MainController {
    @GetMapping(value = "/")
    public String mainPage() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String       username = authentication.getName();
        StringBuffer sbRoles  = new StringBuffer();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();

        while(iterator.hasNext() == true) {
            GrantedAuthority auth = iterator.next();
            if(sbRoles.length() != 0) {
                sbRoles.append(", ");
            }
            sbRoles.append(auth.getAuthority());
        }

        log.trace("username => " + username);
        log.trace("sbRoles  => " + sbRoles);

        List<String> list = Arrays.asList("1value1", "1value2", "1value3");

        log.trace("1. list => " + list);

        list.add("v1alue4");

        log.trace("2. list => " + list);

        List<String> list2 = List.of("2value1", "2value2", "2value3");

        log.trace("1. list2 => " + list2);

        list2.add("2value4");

        log.trace("2. list2 => " + list2);

        return String.format("main Page username = %s, roles = %s", username, sbRoles.toString());
    }
}
