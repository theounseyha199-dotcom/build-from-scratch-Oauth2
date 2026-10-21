package istad.ha.springauthorizationservice.controller;

import java.security.Principal;
import java.util.Map;

import istad.ha.springauthorizationservice.service.CustomCodeService;
import istad.ha.springauthorizationservice.oauth.CustomCodeGrant;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class CustomCodeController {
    private final RegisteredClientRepository clients;
    private final CustomCodeService codes;

    public CustomCodeController(RegisteredClientRepository clients, CustomCodeService codes) {
        this.clients = clients;
        this.codes = codes;
    }

    @PostMapping("/custom-codes")
    public Map<String, String> issue(@RequestParam String clientId, Principal principal) {
        RegisteredClient client = clients.findByClientId(clientId);
        if (client == null || !client.getAuthorizationGrantTypes().contains(CustomCodeGrant.GRANT_TYPE)
            || client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client does not support custom codes");
        }
        return Map.of("code", codes.issue(client.getId(), principal.getName()));
    }
}
