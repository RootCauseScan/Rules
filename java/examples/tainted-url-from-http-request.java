package com.example.demo;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
public class WebsiteTestController {

    private final RestTemplate rest = new RestTemplate();

    @PostMapping("/website/test")
    public String testWebsite(@RequestBody WebsiteTestRequest request) {
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> entity = new HttpEntity<>(headers);
        // ruleid: java-ssrf-resttemplate
        return this.rest.exchange(request.url, HttpMethod.GET, entity, String.class).getBody();
    }

    @GetMapping("/website/get")
    public String fetchWebsite(@RequestParam String url) {
        // ruleid: java-ssrf-resttemplate
        return this.rest.getForObject(url, String.class);
    }
}

class WebsiteTestRequest {
    public String url;
}
