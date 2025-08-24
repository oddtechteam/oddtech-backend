package com.complaint.backend.configurations;

import java.util.Arrays;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

  @Bean
  public CorsFilter corsFilter() {
    // Read comma-separated origins from env; keep local defaults
    String originsEnv = System.getenv().getOrDefault(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:5173,http://localhost:3000"
    );
    var origins = Arrays.stream(originsEnv.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .collect(Collectors.toList());

    CorsConfiguration cfg = new CorsConfiguration();
    cfg.setAllowCredentials(true);                 // if you use cookies; ok to keep true
    cfg.setAllowedOrigins(origins);                // must be explicit when allowCredentials=true
    cfg.setAllowedMethods(Arrays.asList("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
    cfg.setAllowedHeaders(Arrays.asList("*"));     // or list specific headers you use
    cfg.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", cfg);
    return new CorsFilter(source);
  }
}
