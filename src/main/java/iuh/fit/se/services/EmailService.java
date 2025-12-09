package iuh.fit.se.services;

public interface EmailService {
    void sendVerificationEmail(String to, String code);
}