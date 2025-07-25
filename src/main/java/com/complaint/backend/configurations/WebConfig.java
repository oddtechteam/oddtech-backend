package com.complaint.backend.configurations;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Serve /uploads/** from D:\ProjectPost
        registry.addResourceHandler("/uploads/**")
                .addResourceLocations("file:/D:/ProjectPost/");
    }
}