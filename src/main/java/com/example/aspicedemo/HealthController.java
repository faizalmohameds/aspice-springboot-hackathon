package com.example.aspicedemo;

import java.time.Instant;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {
	

    @GetMapping({"/api/status", "/api/health"})
    public Map<String, Object> status() {
        return Map.of(
                "application", "aspice-demo",
                "status", "UP",
                "timestamp", Instant.now().toString()
        );
    }
}
