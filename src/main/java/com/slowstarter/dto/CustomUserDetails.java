package com.slowstarter.dto;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.slowstarter.entity.UserEntity;

public class CustomUserDetails implements UserDetails
{
    private final UserEntity userEntity;
    /**
     * @멤버명 : serialVersionUID
     */
    private static final long serialVersionUID = 1L;

    public CustomUserDetails(UserEntity userEntity)
    {
        this.userEntity = userEntity;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities()
    {
        Collection<GrantedAuthority> collection = new ArrayList<GrantedAuthority>();

        collection.add( () -> userEntity.getRole() );

        return collection;
    }

    @Override
    public String getPassword()
    {
        return userEntity.getPassword();
    }

    @Override
    public String getUsername()
    {
        return userEntity.getUsername();
    }

}
