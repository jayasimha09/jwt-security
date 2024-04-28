package com.jwtsecurity.service.impl;

import com.jwtsecurity.dto.AuthenticationResponse;
import com.jwtsecurity.dto.LoginRequest;
import com.jwtsecurity.dto.SignupRequest;
import com.jwtsecurity.entities.Roles;
import com.jwtsecurity.entities.User;
import com.jwtsecurity.repository.UserRepository;
import com.jwtsecurity.service.AuthService;
import com.jwtsecurity.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Override
    public User signup(SignupRequest signupRequest) {
        logger.info("user-serviceImpl {}", signupRequest);
        var user = User.builder()
                .firstName(signupRequest.getFirstName())
                .lastName(signupRequest.getLastName())
                .email(signupRequest.getEmail())
                .password(passwordEncoder.encode(signupRequest.getPassword()))
                .role(Roles.USER)
                .build();
        return userRepository.save(user);
    }

    @Override
    public AuthenticationResponse login(LoginRequest loginRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword())
        );
        var user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow();
        String JwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().accessToken(JwtToken).build();
    }
}
