package istad.ha.springauthorizationservice.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.security.core.Authentication;

import java.util.Map;

@Controller
public class LoginController {

    @GetMapping("/")
    @ResponseBody
    public Map<String, String> home(Authentication authentication) {
        return Map.of("message", "Signed in", "username", authentication.getName());
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
