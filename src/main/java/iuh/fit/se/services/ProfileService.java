package iuh.fit.se.services;

import iuh.fit.se.dtos.profile.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

public interface ProfileService {
    UserProfileResponse getProfile(Long userId);
    //Thêm MultipartFile
    UserProfileResponse updateProfile(Long userId, UserProfileUpdateRequest request, MultipartFile avatarFile) throws IOException;

    //cho ADMIN
    List<UserProfileResponse> getAllUsers(String role);
    UserProfileResponse updateUserStatus(Long userId, String status);
    void deleteUser(Long userId);
}
