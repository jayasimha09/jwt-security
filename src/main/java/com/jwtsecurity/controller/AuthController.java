package com.jwtsecurity.controller;

import com.jwtsecurity.dto.AuthenticationResponse;
import com.jwtsecurity.dto.LoginRequest;
import com.jwtsecurity.dto.SignupRequest;
import com.jwtsecurity.entities.User;
import com.jwtsecurity.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @PostMapping("/signup")
    public ResponseEntity<User> signup(@RequestBody SignupRequest signupRequest) {
        User user = authService.signup(signupRequest);
        logger.info("user {}", user);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody LoginRequest loginRequest) {
        AuthenticationResponse authenticationResponse = authService.login(loginRequest);
        return ResponseEntity.ok(authenticationResponse);
    }
}
