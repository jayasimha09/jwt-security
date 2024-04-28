package com.jwtsecurity.service;

import com.jwtsecurity.dto.AuthenticationResponse;
import com.jwtsecurity.dto.LoginRequest;
import com.jwtsecurity.dto.SignupRequest;
import com.jwtsecurity.entities.User;

public interface AuthService {
   User signup(SignupRequest signupRequest);
   AuthenticationResponse login(LoginRequest loginRequest);
}
