package istad.ha.springauthorizationservice;

import org.apache.catalina.User;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class SpringAuthorizationServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringAuthorizationServiceApplication.class, args);
    }



}
