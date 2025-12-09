package iuh.fit.se.services.impl;

import iuh.fit.se.dtos.auth.*;
import iuh.fit.se.entities.auth.Role;
import iuh.fit.se.entities.auth.User;
import iuh.fit.se.entities.auth.UserStatus; // Import UserStatus
import iuh.fit.se.exceptions.BadRequestException;
import iuh.fit.se.exceptions.ValidationException;
import iuh.fit.se.repositories.UserRepository;
import iuh.fit.se.services.EmailService; // Import EmailService
import iuh.fit.se.utils.JwtUtil;
import iuh.fit.se.services.AuthService;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime; // Import LocalDateTime
import java.util.*;

@Service
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final EmailService emailService; // Thêm EmailService

    public AuthServiceImpl(UserRepository userRepository, JwtUtil jwtUtil, EmailService emailService) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.emailService = emailService;
    }

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request) {

        //Kiem tra trung email
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new BadRequestException("Email already exists in the system");
        }

        //Kiem tra xac nhan mat khau
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            List<Map<String, String>> errors = List.of(
                    Map.of("field", "confirmPassword", "message", "Password confirmation does not match")
            );
            throw new ValidationException(errors);
        }

        //Ma hoa mat khau bang BCrypt
        String hashed = BCrypt.hashpw(request.getPassword(), BCrypt.gensalt());

        //Tao user moi
        User user = new User();
        user.setFullName(request.getFullName());
        user.setEmail(request.getEmail());
        user.setPassword(hashed);
        user.setRole(request.getRole() == null ? Role.USER : request.getRole());

        user.setStatus(UserStatus.INACTIVE);

        // Tao ma verify
        String code = String.valueOf(new Random().nextInt(900000) + 100000); // Random 6 số
        user.setVerificationCode(code);
        user.setVerificationExpiration(LocalDateTime.now().plusMinutes(15)); // Hết hạn sau 15p

        userRepository.save(user);

        // Gửi email
        emailService.sendVerificationEmail(user.getEmail(), code);

        //Tra ket qua
        RegisterResponse response = new RegisterResponse();
        response.setSuccess(true);
        response.setEmail(user.getEmail());
        response.setRole(user.getRole());
        response.setMessage("Registration successful. Please check your email to verify account.");

        return response;
    }
    //Verify
    public void verifyAccount(VerifyRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BadRequestException("User not found"));

        //kiem tra tk da active chua
        if (user.getStatus() == UserStatus.ACTIVE) {
            throw new BadRequestException("Account is already verified");
        }

        //Kiem tra ma code het han chua
        if (user.getVerificationExpiration() == null ||
                user.getVerificationExpiration().isBefore(LocalDateTime.now())) {
            throw new BadRequestException("Verification code has expired");
        }

        //Kiem tra ma code co dung hay ko
        if (user.getVerificationCode() == null ||
                !user.getVerificationCode().equals(request.getVerificationCode())) {
            throw new BadRequestException("Invalid verification code");
        }

        //Kich hoat tk
        user.setStatus(UserStatus.ACTIVE);
        user.setVerificationCode(null);
        user.setVerificationExpiration(null);

        userRepository.save(user);
    }

    @Override
    @Transactional(readOnly = true)
    public LoginResponse login(LoginRequest request) {

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BadRequestException("Invalid email or password"));

        if (!BCrypt.checkpw(request.getPassword(), user.getPassword())) {
            throw new BadRequestException("Invalid email or password");
        }

        switch (user.getStatus()) {
            case INACTIVE -> throw new BadRequestException("Your account is not verified. Please check email.");
            case BANNED -> throw new BadRequestException("Your account has been banned.");
            default -> {}
        }

        String token = jwtUtil.generateToken(user);

        LoginResponse response = new LoginResponse();
        response.setSuccess(true);
        response.setToken(token);
        response.setRole(user.getRole());
        response.setMessage("Login successful");

        return response;
    }
}