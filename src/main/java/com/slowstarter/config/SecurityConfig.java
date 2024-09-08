package com.slowstarter.config;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;

import com.slowstarter.component.JwtComponent;
import com.slowstarter.filter.CustomLogoutFilter;
import com.slowstarter.filter.JwtFilter;
import com.slowstarter.filter.LoginFilter;
import com.slowstarter.service.RefreshTokenService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtComponent jwtComponent;
    private final RefreshTokenService refreshTokenService;
    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JwtComponent jwtComponent, RefreshTokenService refreshTokenService) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtComponent                = jwtComponent;
        this.refreshTokenService         = refreshTokenService;
    }

    //AuthenticationManager Bean 등록
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // cors 설정
        httpSecurity
            .cors( (customizer) ->
                customizer.configurationSource(( request ) -> {
                    CorsConfiguration configuration = new CorsConfiguration();

                    configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:3001"));
                    configuration.setAllowedMethods(Collections.singletonList("*"));
                    configuration.setAllowCredentials(true);
                    configuration.setAllowedHeaders(Collections.singletonList("*"));
                    configuration.setMaxAge(3600L);
                    configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                    return configuration;
                })
            );

        //csrf disable
        httpSecurity
            .csrf( (customizer) -> customizer.disable() );

        //From 로그인 방식 disable
        httpSecurity
            .formLogin( (customizer) -> customizer.disable() );

        //http basic 인증 방식 disable
        httpSecurity
            .httpBasic( (customizer) -> customizer.disable() );

        //경로별 인가 작업
        httpSecurity
            .authorizeHttpRequests( (customizer) ->
                customizer.requestMatchers("/", "/reissue", "/login", "/join").permitAll()
                          .requestMatchers("/admin").hasRole("ADMIN")
                          .anyRequest().authenticated());

        // JwtFilter 로그인 이후 접속에 대한 token 확인 후 인증
        httpSecurity
            .addFilterBefore(new JwtFilter(this.jwtComponent), LoginFilter.class);

        //필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
        httpSecurity
            .addFilterAt(new LoginFilter(this.authenticationManager(this.authenticationConfiguration), this.jwtComponent, this.refreshTokenService), UsernamePasswordAuthenticationFilter.class);

        // JwtFilter 로그인 이후 접속에 대한 token 확인 후 인증
        httpSecurity
            .addFilterBefore(new CustomLogoutFilter(this.jwtComponent, this.refreshTokenService), LogoutFilter.class);

        //세션 설정
        httpSecurity
            .sessionManagement( (customizer) ->
                customizer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return httpSecurity.build();
    }
}
