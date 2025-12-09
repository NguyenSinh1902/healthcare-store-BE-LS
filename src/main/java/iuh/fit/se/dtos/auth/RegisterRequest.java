package iuh.fit.se.dtos.auth;

import iuh.fit.se.entities.auth.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class RegisterRequest {

    @NotBlank(message = "Full name is required")
    @Pattern(regexp = "^[\\p{L}\\s]+$", message = "Full name must not contain numbers or special characters")
    private String fullName;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,50}$",
            message = "Password must contain at least one uppercase, one lowercase, one number, one special character, and be 8-50 characters long")
    private String password;

    @NotBlank(message = "Confirm password is required")
    private String confirmPassword;

    @Pattern(regexp = "^0\\d{9,10}$", message = "Invalid phone number format")
    private String phone;

    private Role role;

    public RegisterRequest() {
        this.role = Role.USER;
    }

    // --- GETTERS & SETTERS ---
    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        // Neu role null mac dinh la USER
        if (role == null) {
            this.role = Role.USER;
        } else {
            this.role = role;
        }
    }
}
