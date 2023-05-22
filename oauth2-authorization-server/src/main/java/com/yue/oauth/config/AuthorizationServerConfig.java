package com.yue.oauth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.yue.oauth.pojo.entity.security.SecurityUser;
import com.yue.oauth.pojo.entity.security.SecurityUserMixin;
import com.yue.oauth.service.impl.OidcUserInfoService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collection;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    private final OidcUserInfoService userInfoService;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        http.exceptionHandling(exception ->
                exception.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate){
        RegisteredClient registeredClient = RegisteredClient.withId("test")
                // 客户端id 需要唯一
                .clientId("test")
                // 客户端密码
                .clientSecret(passwordEncoder.encode("123123"))
                //客户端名字
                .clientName("test")
                // 可以基于 basic 的方式和授权服务器进行认证
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // 授权码
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // 刷新token
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // 客户端模式
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                // 密码模式 已过时
//                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                // 简化模式，已过时，不推荐
//                .authorizationGrantType(AuthorizationGrantType.IMPLICIT)
                // 重定向url
                .redirectUri("http://127.0.0.1:9999")
                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/admin")
                // 客户端申请的作用域，也可以理解这个客户端申请访问用户的哪些信息，比如：获取用户信息，获取用户照片等
                .scope("read")
                .scope("write")
                .scope("openid")
                .scope("profile")
                .scope("email")
                .scope("address")
                .clientSettings(ClientSettings.builder()
                        // 是否需要用户确认一下客户端需要获取用户的哪些权限
                        //比如：客户端需要获取用户的 用户信息、用户照片 但是此处用户可以控制只给客户端授权获取 用户信息。
                        .requireAuthorizationConsent(true)
                        .build()
                )
                .tokenSettings(TokenSettings.builder()
                         // accessToken 的有效期
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        // refreshToken 的有效期
                        .refreshTokenTimeToLive(Duration.ofHours(3))
                         // 是否可重用刷新令牌
                        .reuseRefreshTokens(true)
                        .build()
                )
                .build();
        //http://authorization:8080/oauth2/authorize?response_type=code&client_id=test&scope=profile%20email%20openid%20email%20address&redirect_uri=http://127.0.0.1:9999
        JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        if(jdbcRegisteredClientRepository.findByClientId("test")==null){
            jdbcRegisteredClientRepository.save(registeredClient);
        }
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(){
        KeyPair keyPair= generateRsaKey();
        //生成公钥
        RSAPublicKey aPublic = (RSAPublicKey) keyPair.getPublic();
        //生成私钥
        RSAPrivateKey aPrivate = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rasKey = new RSAKey
                .Builder(aPublic)
                .privateKey(aPrivate)
                .keyID(UUID.randomUUID()
                        .toString())
                .build();
        JWKSet jwkSet = new JWKSet(rasKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource){
        // jwt解密
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 设置一些断点的路径，比如获取token,授权端点等
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().issuer("http://authorization:8080").build();
    }


    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository){
        // 保存授权信息，授权服务器会颁发一个token,用这个进行保存
        JdbcOAuth2AuthorizationService authorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
        class CustomOAuth2AuthorizationRowMapper extends JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper {
            public CustomOAuth2AuthorizationRowMapper(RegisteredClientRepository registeredClientRepository) {
                super(registeredClientRepository);
                this.getObjectMapper().addMixIn(SecurityUser.class, SecurityUserMixin.class);
            }
        }
        CustomOAuth2AuthorizationRowMapper oAuth2AuthorizationRowMapper =
                new CustomOAuth2AuthorizationRowMapper(registeredClientRepository);
        authorizationService.setAuthorizationRowMapper(oAuth2AuthorizationRowMapper);
        return authorizationService;
    }

    @Bean
    public OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService(JdbcTemplate jdbcTemplate,RegisteredClientRepository registeredClientRepository){
        // 如果是授权码模式，可能客户端申请了多个权限，比如获取用户信息，修改用户信息，此Service处理的是给这个客户端哪些权限，比如只给获取用户信息权限
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate,registeredClientRepository);
    }

    // 自定义ID token跟AccessToken
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer(){
        return context -> {
             if(OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())){
                OidcUserInfo userInfo = userInfoService.loadUser(
                        context.getPrincipal().getName());
                context.getClaims().claims(claims ->
                        claims.putAll(userInfo.getClaims()));
             }
//            Collection<? extends GrantedAuthority> authorities = context.getPrincipal().getAuthorities();
//            context.getClaims().claim("scope",authorities);
            context.getJwsHeader().header("client-id",context.getRegisteredClient().getClientId());
        };
    }

    private KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
            rsa.initialize(2048);
            return rsa.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
