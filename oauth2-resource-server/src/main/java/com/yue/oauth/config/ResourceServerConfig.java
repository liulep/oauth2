package com.yue.oauth.config;

import com.alibaba.fastjson2.JSON;
import com.yue.oauth.pojo.entity.R;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

@Configuration
@EnableWebSecurity
public class ResourceServerConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;


    @Autowired
    private RestTemplateBuilder restTemplateBuilder;

    /**
     * 资源服务器主要配置
     * 资源服务器要校验令牌，校验令牌就需要公开，公钥从哪里拿
     * 资源服务哪些资源是公开的？
     * 哪些资源必须需要合法令牌
     */
    @Bean
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(request ->
                request.requestMatchers("/res1").hasAnyAuthority("ROLE_ADMIN")
                        .requestMatchers("/res2").hasAnyAuthority("SCOPE_write")
                        .anyRequest()
                        .authenticated())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 ->
                                oauth2.jwt(jwt ->
                                    jwt.decoder(jwtDecoder(restTemplateBuilder))
                                       .jwtAuthenticationConverter(jwtAuthenticationConverter())
                                ).bearerTokenResolver(bearerTokenResolver())

                )
                .exceptionHandling(ex ->
                        ex.authenticationEntryPoint(new YueAuthenticationEntryPoint())
                                .accessDeniedHandler(new YueAccessDeniedHandler())
                );
        return http.build();
    }

    //配置Claims集映射
    static class ScopeSubClaimAdapter implements Converter<Map<String,Object>,Map<String,Object>>{
        private final MappedJwtClaimSetConverter delegate =MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
        @Override
        public Map<String, Object> convert(Map<String, Object> claims) {
            System.out.println(claims.get("scope"));
            return claims;
        }
    }

    //提取权限
    private JwtAuthenticationConverter jwtAuthenticationConverter(){
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("scope");
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("SCOPE_");
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    // 检验JWT是否合法
    public JwtDecoder jwtDecoder(RestTemplateBuilder builder){
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
                .withJwkSetUri("http://authorization:8080/oauth2/jwks")
                .restOperations(builder
                        .setConnectTimeout(Duration.ofSeconds(60))
                        .setReadTimeout(Duration.ofSeconds(60))
                        .build())
                .build();
        jwtDecoder.setJwtValidator(JwtValidators.createDefault());
        //jwtDecoder.setClaimSetConverter(new ScopeSubClaimAdapter());
        return jwtDecoder;
    }

    // 请请求中获取token
    private BearerTokenResolver bearerTokenResolver(){
        DefaultBearerTokenResolver defaultBearerTokenResolver = new DefaultBearerTokenResolver();
        defaultBearerTokenResolver.setBearerTokenHeaderName(HttpHeaders.AUTHORIZATION);
        //是否可以从form表单中获取token
        defaultBearerTokenResolver.setAllowFormEncodedBodyParameter(false);
        //是否可以从uri请求中获取token
        defaultBearerTokenResolver.setAllowUriQueryParameter(false);
        return defaultBearerTokenResolver;
    }

    //没有登录时
    static class YueAuthenticationEntryPoint implements AuthenticationEntryPoint{
        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
            if(authException instanceof OAuth2AuthenticationException exception){
                OAuth2Error error=exception.getError();
            }
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
            response.getWriter().write(JSON.toJSONString(R.error().message("请先登录！")));
        }
    }

    //登录后无权限时
    static class YueAccessDeniedHandler implements AccessDeniedHandler{
        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
            response.getWriter().write(JSON.toJSONString(R.error().message("您无权访问！")));
        }
    }


}
