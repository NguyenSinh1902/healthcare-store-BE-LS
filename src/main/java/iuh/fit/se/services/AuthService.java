package iuh.fit.se.services;

import iuh.fit.se.dtos.auth.LoginRequest;
import iuh.fit.se.dtos.auth.LoginResponse;
import iuh.fit.se.dtos.auth.RegisterRequest;
import iuh.fit.se.dtos.auth.RegisterResponse;

public interface AuthService {
    RegisterResponse register(RegisterRequest request);
    LoginResponse login(LoginRequest request);
}
