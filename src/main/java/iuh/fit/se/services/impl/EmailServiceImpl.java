package iuh.fit.se.services.impl;

import iuh.fit.se.services.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;

@Service
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    public EmailServiceImpl(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    @Async
    public void sendVerificationEmail(String to, String code) {

        String senderName = "GREENPLUS Support";

        String subject = "Verify your account - GREENPLUS Healthcare";

        String content = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    .email-container {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background-color: #f0f2f5;
                        padding: 40px 20px;
                    }
                    .email-card {
                        background-color: #ffffff;
                        max-width: 550px;
                        margin: 0 auto;
                        padding: 40px;
                        border-radius: 12px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                        text-align: center;
                        border-top: 5px solid #2E7D32; /* Viền xanh lá đậm */
                    }
                    .header {
                        font-size: 28px;
                        font-weight: bold;
                        color: #2E7D32; /* Màu xanh thương hiệu */
                        margin-bottom: 10px;
                        letter-spacing: 1px;
                    }
                    .sub-header {
                        font-size: 14px;
                        color: #666;
                        margin-bottom: 30px;
                        font-style: italic;
                    }
                    .text {
                        color: #444444;
                        font-size: 16px;
                        line-height: 1.6;
                        margin-bottom: 20px;
                    }
                    .code-box {
                        display: inline-block;
                        background-color: #E8F5E9; /* Nền xanh nhạt */
                        color: #1B5E20; /* Chữ xanh đậm */
                        font-size: 36px;
                        font-weight: 700;
                        padding: 15px 40px;
                        border-radius: 8px;
                        letter-spacing: 8px;
                        margin: 25px 0;
                        border: 1px dashed #2E7D32;
                    }
                    .footer {
                        margin-top: 40px;
                        padding-top: 20px;
                        border-top: 1px solid #eee;
                        font-size: 12px;
                        color: #888888;
                    }
                    .highlight {
                        font-weight: bold;
                        color: #2E7D32;
                    }
                </style>
            </head>
            <body>
                <div class="email-container">
                    <div class="email-card">
                        <div class="header">GREENPLUS</div>
                        <div class="sub-header">Your Trusted Healthcare Partner</div>
                        
                        <p class="text">Hello,</p>
                        <p class="text">Welcome to <span class="highlight">GREENPLUS</span>! To ensure the security of your account and start your health journey with us, please verify your email address.</p>
                        
                        <div class="code-box">%s</div>
                        
                        <p class="text">This verification code is valid for <strong>15 minutes</strong>.</p>
                        <p class="text" style="font-size: 14px; color: #777;">If you did not create an account with GREENPLUS, you can safely ignore this email.</p>
                        
                        <div class="footer">
                            &copy; 2025 GREENPLUS Pharmacy. All rights reserved.<br>
                            Taking care of your life.
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(code);

        MimeMessage message = mailSender.createMimeMessage();

        try {
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, senderName);

            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(content, true);

            mailSender.send(message);

        } catch (MessagingException | UnsupportedEncodingException e) {
            System.err.println("Failed to send email: " + e.getMessage());
        }
    }
}