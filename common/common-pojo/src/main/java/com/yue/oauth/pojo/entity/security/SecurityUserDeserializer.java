package com.yue.oauth.pojo.entity.security;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.io.IOException;
import java.util.Collection;
import java.util.Set;

public class SecurityUserDeserializer extends JsonDeserializer<SecurityUser> {

    private static final TypeReference<Collection<? extends SimpleGrantedAuthority>> SIMPLE_GRANTED_AUTHORITY_COLLECTION = new TypeReference<Collection<? extends SimpleGrantedAuthority>>() {
    };

    public SecurityUserDeserializer(){}

    @Override
    public SecurityUser deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JacksonException {
        ObjectMapper mapper = (ObjectMapper)jp.getCodec();
        JsonNode jsonNode = (JsonNode)mapper.readTree(jp);
        Collection<? extends SimpleGrantedAuthority> authorities = mapper.convertValue(jsonNode.get("authorities"), SIMPLE_GRANTED_AUTHORITY_COLLECTION);
        JsonNode passwordNode = this.readJsonNode(jsonNode, "password");
        String username = this.readJsonNode(jsonNode, "username").asText();
        String password = passwordNode.asText("");
        boolean enabled = this.readJsonNode(jsonNode, "enabled").asBoolean();
        boolean accountNonExpired = this.readJsonNode(jsonNode, "accountNonExpired").asBoolean();
        boolean credentialsNonExpired = this.readJsonNode(jsonNode, "credentialsNonExpired").asBoolean();
        boolean accountNonLocked = this.readJsonNode(jsonNode, "accountNonLocked").asBoolean();
        SecurityUser securityUser=SecurityUser.builder()
                .username(username)
                .password(password)
                .enabled(enabled)
                .accountNonExpired(accountNonExpired)
                .credentialsNonExpired(credentialsNonExpired)
                .accountNonLocked(accountNonLocked)
                .authorities(authorities)
                .build();
        if (passwordNode.asText((String)null) == null) {
            securityUser.setPassword(null);
        }
        return securityUser;
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return (JsonNode)(jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance());
    }
}
