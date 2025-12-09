package iuh.fit.se.dtos.profile;

import jakarta.validation.constraints.*;
import java.time.LocalDate;

public class UserProfileUpdateRequest {

    @NotBlank(message = "Full name is required")
    private String fullName;

    @Pattern(regexp = "^0\\d{9,10}$", message = "Invalid phone number")
    private String phone;

    private String address;

    private LocalDate dateOfBirth;

    private String avatarUrl;

    public UserProfileUpdateRequest() {
    }

    public UserProfileUpdateRequest(String fullName, String phone, String address, LocalDate dateOfBirth, String avatarUrl) {
        this.fullName = fullName;
        this.phone = phone;
        this.address = address;
        this.dateOfBirth = dateOfBirth;
        this.avatarUrl = avatarUrl;
    }

    // Getters & Setters

    public @NotBlank(message = "Full name is required") String getFullName() {
        return fullName;
    }

    public void setFullName(@NotBlank(message = "Full name is required") String fullName) {
        this.fullName = fullName;
    }

    public @Pattern(regexp = "^0\\d{9,10}$", message = "Invalid phone number") String getPhone() {
        return phone;
    }

    public void setPhone(@Pattern(regexp = "^0\\d{9,10}$", message = "Invalid phone number") String phone) {
        this.phone = phone;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public LocalDate getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(LocalDate dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public String getAvatarUrl() {
        return avatarUrl;
    }

    public void setAvatarUrl(String avatarUrl) {
        this.avatarUrl = avatarUrl;
    }
}
