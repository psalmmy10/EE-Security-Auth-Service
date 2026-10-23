package com.pay.auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.pay.auth.constant.ApiPaths;
import com.pay.auth.security.e2e.E2EEnforcementInterceptor;

@Configuration
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {

    private final E2EEnforcementInterceptor e2eEnforcementInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(e2eEnforcementInterceptor).addPathPatterns(ApiPaths.API_V1 + "/**");
    }
}
