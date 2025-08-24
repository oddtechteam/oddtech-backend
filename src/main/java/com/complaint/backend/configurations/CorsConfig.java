package com.complaint.backend.configurations;

import java.util.Arrays;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfig {

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    // Comma-separated origins from env; local defaults for dev
    String originsEnv = System.getenv().getOrDefault(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:5173,http://localhost:3000"
    );

    var origins = Arrays.stream(originsEnv.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .collect(Collectors.toList());

    CorsConfiguration cfg = new CorsConfiguration();
    // With credentials=true, you MUST use explicit origins (not "*")
    cfg.setAllowedOrigins(origins);
    cfg.setAllowedMethods(Arrays.asList("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
    cfg.setAllowedHeaders(Arrays.asList("*")); // or list: "Authorization","Content-Type","x_api_key"
    cfg.setAllowCredentials(true);
    cfg.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", cfg);
    return source;
  }
}
