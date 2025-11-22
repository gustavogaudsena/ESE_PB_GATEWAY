package br.com.housemanager.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/actuator/health").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                );

        return http.build();
    }

    @Bean
    public Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var authorities = new ArrayList<GrantedAuthority>();

            var realm = (Map<String, Object>) jwt.getClaim("realm_access");
            if (realm != null) {
                var roles = (Collection<String>) realm.get("roles");
                if (roles != null) {
                    roles.forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));
                }
            }

            var resource = (Map<String, Object>) jwt.getClaim("resource_access");
            if (resource != null) {
                var client = (Map<String, Object>) resource.get("stockflow");
                if (client != null) {
                    var roles = (Collection<String>) client.get("roles");
                    if (roles != null) {
                        roles.forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));
                    }
                }
            }

            return Flux.fromIterable(authorities);
        });

        return converter;
    }
//    @Bean
//    Converter<Jwt, ? extends AbstractAuthenticationToken> jwtConverter() {
//        return jwt -> {
//
//            var authorities = new ArrayList<GrantedAuthority>();
//            var realm = (Map<String, Object>) jwt.getClaim("realm_access");
//            if (realm != null) {
//                var roles = (Collection<String>) realm.get("roles");
//                if (roles != null) {
//                    roles.forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));
//                }
//            }
//            var resource = (Map<String, Object>) jwt.getClaim("resource_access");
//            if (resource != null) {
//                var client = (Map<String, Object>) resource.get("stockflow");
//                if (client != null) {
//                    var roles = (Collection<String>) client.get("roles");
//                    if (roles != null) {
//                        roles.forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));
//                    }
//                }
//            }
//            return new JwtAuthenticationToken(jwt, authorities);
//        };
//    }
}
