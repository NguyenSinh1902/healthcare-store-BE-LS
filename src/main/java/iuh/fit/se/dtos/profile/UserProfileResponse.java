package iuh.fit.se.dtos.profile;

import iuh.fit.se.entities.auth.Role;
import iuh.fit.se.entities.auth.UserStatus;
import java.time.LocalDate;

public class UserProfileResponse {
    private Long idUser;
    private String fullName;
    private String email;
    private String phone;
    private String address;
    private LocalDate dateOfBirth;
    private String avatarUrl;
    private Role role;
    private UserStatus status;
    private String createdAt;

    public UserProfileResponse() {
    }

    public UserProfileResponse(Long idUser, String fullName, String email, String phone, String address, LocalDate dateOfBirth, String avatarUrl, Role role, UserStatus status, String createdAt) {
        this.idUser = idUser;
        this.fullName = fullName;
        this.email = email;
        this.phone = phone;
        this.address = address;
        this.dateOfBirth = dateOfBirth;
        this.avatarUrl = avatarUrl;
        this.role = role;
        this.status = status;
        this.createdAt = createdAt;
    }

    public Long getIdUser() {
        return idUser;
    }

    public void setIdUser(Long idUser) {
        this.idUser = idUser;
    }

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

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
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

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }
}
