package com.example.apigateway;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/user")
    public Mono<Map<String, Object>> getCurrentUser(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        if (authentication == null || !(authentication.getPrincipal() instanceof JwtUserDetails)) {
            response.put("authenticated", false);
            return Mono.just(response);
        }
        JwtUserDetails userDetails = (JwtUserDetails) authentication.getPrincipal();
        response.put("authenticated", true);
        response.put("userId", userDetails.getUserId());
        response.put("email", userDetails.getEmail());
        response.put("authorities", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        return Mono.just(response);
    }
}
