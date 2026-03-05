package com.example.apigateway;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping("/public")
    public Mono<Map<String, Object>> publicEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a public endpoint - no authentication required");
        response.put("status", "success");
        response.put("timestamp", System.currentTimeMillis());
        return Mono.just(response);
    }

    @GetMapping("/protected")
    public Mono<Map<String, Object>> protectedEndpoint(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Authentication successful!");
        response.put("status", "success");
        response.put("authenticated", true);
        response.put("timestamp", System.currentTimeMillis());

        if (authentication != null && authentication.getPrincipal() instanceof JwtUserDetails) {
            JwtUserDetails userDetails = (JwtUserDetails) authentication.getPrincipal();
            response.put("email", userDetails.getEmail());
            response.put("userId", userDetails.getUserId());
            response.put("authorities", authentication.getAuthorities());
        }

        return Mono.just(response);
    }

    @GetMapping("/user-info")
    public Mono<Map<String, Object>> getUserInfo(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();

        if (authentication != null && authentication.getPrincipal() instanceof JwtUserDetails) {
            JwtUserDetails userDetails = (JwtUserDetails) authentication.getPrincipal();
            response.put("userId", userDetails.getUserId());
            response.put("email", userDetails.getEmail());
            response.put("authenticated", authentication.isAuthenticated());
            response.put("authorities", authentication.getAuthorities());
        } else {
            response.put("error", "No authentication found");
        }

        return Mono.just(response);
    }

    @GetMapping("/health")
    public Mono<Map<String, Object>> healthCheck(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "Gateway is running");
        response.put("authenticated", authentication != null);
        response.put("timestamp", System.currentTimeMillis());

        if (authentication != null && authentication.getPrincipal() instanceof JwtUserDetails) {
            JwtUserDetails userDetails = (JwtUserDetails) authentication.getPrincipal();
            response.put("user", userDetails.getEmail());
        }

        return Mono.just(response);
    }

    @GetMapping("/get-user-id")
    public Mono<Map<String, Object>> getUserId(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();

        if (authentication != null && authentication.getPrincipal() instanceof JwtUserDetails) {
            JwtUserDetails userDetails = (JwtUserDetails) authentication.getPrincipal();
            response.put("userId", userDetails.getUserId());
            response.put("email", userDetails.getEmail());
            response.put("status", "success");
        } else {
            response.put("error", "User not authenticated");
            response.put("status", "failed");
        }

        return Mono.just(response);
    }
}
