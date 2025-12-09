package iuh.fit.se.controllers;

import iuh.fit.se.dtos.auth.*;
import iuh.fit.se.services.AuthService;
import iuh.fit.se.services.impl.AuthServiceImpl; // Cast nếu cần hoặc dùng Interface nếu đã thêm method
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    //API Verify
    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody VerifyRequest request) {
        if (authService instanceof AuthServiceImpl) {
            ((AuthServiceImpl) authService).verifyAccount(request);
        } else {
            // authService.verifyAccount(request);
        }

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Account verified successfully"
        ));
    }
}