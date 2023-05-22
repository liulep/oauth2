package com.yue.oauth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.function.Supplier;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class DefaultSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(request ->
                request.requestMatchers("/login").permitAll()
                        .anyRequest()
                        .authenticated()
        )
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    static class YueManager implements AuthorizationManager<RequestAuthorizationContext>{
        @Override
        public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext requestAuthorizationContext) {
            Authentication auth = authentication.get();
            AuthorizationDecision authorizationDecision = new AuthorizationDecision(false);
            if(auth instanceof UserDetails userDetails){
                if(userDetails.getAuthorities().contains(new SimpleGrantedAuthority(requestAuthorizationContext.getRequest().getRequestURI()))){
                    return new AuthorizationDecision(true);
                }
            }
            return new AuthorizationDecision(false);
        }
    }
}
