package com.complaint.backend.configurations;

import java.io.IOException;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.complaint.backend.services.jwt.UserService;
import com.complaint.backend.utils.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;



@Component
@RequiredArgsConstructor

    public class JwtAuthenticationFilter extends OncePerRequestFilter{

    private final JwtUtil jwtUtil;

    private final UserService userService;

   @Override
   
   protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws
   ServletException, IOException{

   
   final String authHeader = request.getHeader (  "Authorization");
   final String jwt;
   final String userEmail;
   if (StringUtils.isEmpty(authHeader) || !StringUtils.startsWith(authHeader, "Bearer")){  // isNoneEmpty --> isEmpty ref(ChatGPT)
            filterChain.doFilter(request, response);
            return;
   }
   jwt = authHeader.substring(7);
   userEmail = jwtUtil.extractUsername(jwt);
   if (StringUtils.isNotEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null){
        UserDetails userDetails = userService.userDetailsService().loadUserByUsername(userEmail);

        if (jwtUtil.isTokenValid(jwt, userDetails)) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
            
            authenticationToken.setDetails( new WebAuthenticationDetailsSource().buildDetails(request));
            securityContext.setAuthentication(authenticationToken);
            SecurityContextHolder.setContext(securityContext);

                }
            }

            filterChain.doFilter(request, response);
        }
        
    }
