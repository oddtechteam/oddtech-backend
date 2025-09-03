package com.complaint.backend.services.auth;//package com.complaint.backend.services.auth;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
//import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
//import org.springframework.security.oauth2.core.user.OAuth2User;
//import org.springframework.stereotype.Service;
//
//import com.complaint.backend.services.jwt.UserService;
//
//@Service
//public class CustomOAuth2UserService extends DefaultOAuth2UserService {
//
//    @Autowired
//    private UserService userService;
//
//    @Override
//    public OAuth2User loadUser(OAuth2UserRequest request) {
//        OAuth2User oAuth2User = super.loadUser(request);
//
//        String email = oAuth2User.getAttribute("email");
//        String name = oAuth2User.getAttribute("name");
//
//        userService.createGoogleUser(email, name); // ✅ Your existing method
//
//        return oAuth2User;
//    }
//}