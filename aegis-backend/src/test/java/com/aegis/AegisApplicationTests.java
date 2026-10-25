package com.aegis;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("local")
class AegisApplicationTests {

    @Test
    void contextLoads() {
        // Verifies the Spring Boot application context loads successfully
    }
}
