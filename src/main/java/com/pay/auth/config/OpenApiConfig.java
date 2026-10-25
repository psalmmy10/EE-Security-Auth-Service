
package com.pay.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI authServiceOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Pay Auth Service API")
                        .description("""
                                Authentication API using end-to-end
                                encrypted request and response payloads.
                                """)
                        .version("1.0.0"))
                .addServersItem(new Server()
                        .url("/")
                        .description("Current server"));
    }
}
