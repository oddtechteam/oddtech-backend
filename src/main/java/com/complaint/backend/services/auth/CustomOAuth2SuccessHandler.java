package com.complaint.backend.services.auth;//package com.complaint.backend.services.auth;
//import java.io.IOException;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.oauth2.core.user.OAuth2User;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.stereotype.Component;
//
//import com.complaint.backend.services.jwt.UserService;
//import com.complaint.backend.utils.JwtUtil;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//
//@Component
//public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {
//
//
//    @Autowired
//    private UserService userService; // ✅ Your existing service
//
//    @Autowired
//    private JwtUtil jwtUtil;
//
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//                                        Authentication authentication) throws IOException {
//
//        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
//        String email = oAuth2User.getAttribute("email");
//        String name = oAuth2User.getAttribute("name");
//
//        // 1. Create the user if not exists
//        userService.createGoogleUser(email, name);
//
//        // 2. Load user from DB using UserService
//        org.springframework.security.core.userdetails.User user = userService.findFirstByEmail(email)
//                .orElseThrow(() -> new RuntimeException("User not found"));
//
//        // 3. Manually convert User to UserDetails
//        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
//                .username(user.getEmail())
//                .password(user.getPassword() == null ? "" : user.getPassword()) // empty for Google users
//                .roles(user.getUserRole().name())
//                .build();
//
//        // 4. Generate JWT
//        String token = jwtUtil.generateToken(userDetails);
//
//        // 5. Redirect with token
//        response.sendRedirect("http://localhost:5173/oauth2/redirect?token=" + token);
//    }
//}
