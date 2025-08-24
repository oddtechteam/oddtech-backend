package com.complaint.backend.configurations;

import java.util.Arrays;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.complaint.backend.enums.UserRole;
import com.complaint.backend.services.jwt.UserService;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfiguration {

    private final UserService userService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            // enable CORS using the bean below
            .cors(cors -> {})
            .authorizeHttpRequests(auth -> auth
                // Health for Railway
                .requestMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll()
                // Preflight must pass
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // OAuth endpoints (if you use Google sign-in)
                .requestMatchers("/oauth2/**", "/login/oauth2/**").permitAll()

                // Public auth endpoints
                .requestMatchers("/api/auth/**").permitAll()

                // Your rules (kept as-is; one tweak noted below)
                .requestMatchers("/api/admin/**").hasAuthority(UserRole.ADMIN.name())
                .requestMatchers("/api/users/all").permitAll()
                .requestMatchers("/api/assets/**").permitAll()
                .requestMatchers("/api/assignments/**").permitAll()
                .requestMatchers("/api/note/**").hasAnyAuthority(UserRole.ADMIN.name(), UserRole.EMPLOYEE.name())
                .requestMatchers("/api/issues").hasAuthority(UserRole.EMPLOYEE.name())
                .requestMatchers("/api/issues/**").hasAuthority(UserRole.ADMIN.name())
                .requestMatchers("/api/employee/**").hasAuthority(UserRole.EMPLOYEE.name())
                .requestMatchers("/api/post/**").hasAnyAuthority(UserRole.ADMIN.name(), UserRole.EMPLOYEE.name())
                .requestMatchers("/uploads/**").permitAll()
                .requestMatchers("/api/postcomment/**").hasAnyAuthority(UserRole.ADMIN.name(), UserRole.EMPLOYEE.name())
                .requestMatchers("/api/employee/translate").hasAuthority(UserRole.EMPLOYEE.name())
                // Ant patterns don't support regex; keep authority style consistent:
                .requestMatchers("/api/assignments/*/return").hasAuthority(UserRole.ADMIN.name())
                .requestMatchers("/api/visitors").permitAll()
                .requestMatchers("/api/visitors/*/approve").hasAuthority(UserRole.ADMIN.name())
                .requestMatchers("/api/visitors/*/exit").hasAuthority(UserRole.ADMIN.name())
                .requestMatchers("/api/visitors/**").hasAnyAuthority(UserRole.EMPLOYEE.name(), UserRole.ADMIN.name())
                .requestMatchers("/api/documents/**").permitAll()
                .requestMatchers("/api/attendance/records").permitAll()
                .requestMatchers("/api/attendance/check-in-out").permitAll()

                .anyRequest().authenticated()
            )
            .sessionManagement(m -> m.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authenticationProvider())
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // CORS driven by env var CORS_ALLOWED_ORIGINS (comma-separated)
   

    @Bean public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userService.userDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
