package iuh.fit.se.controllers;

import iuh.fit.se.dtos.profile.*;
import iuh.fit.se.services.ProfileService;
import iuh.fit.se.utils.JwtUtil;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/profile")
@CrossOrigin(origins = "*")
public class ProfileController {

    private final ProfileService profileService;
    private final JwtUtil jwtUtil;

    public ProfileController(ProfileService profileService, JwtUtil jwtUtil) {
        this.profileService = profileService;
        this.jwtUtil = jwtUtil;
    }

    //lấy ID từ Token
    private Long getUserIdFromToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            return jwtUtil.extractUserId(token);
        }
        throw new RuntimeException("Unauthorized: Token is missing or invalid");
    }

    //tạo response
    private ResponseEntity<Map<String, Object>> buildResponse(HttpStatus status, String message, Object data) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", message);
        if (data != null) {
            body.put("data", data);
        }
        return ResponseEntity.status(status).body(body);
    }


    //Get My Profile
    @GetMapping("/my-profile")
    public ResponseEntity<Map<String, Object>> getMyProfile(@RequestHeader("Authorization") String authHeader) {
        Long userId = getUserIdFromToken(authHeader);
        UserProfileResponse profile = profileService.getProfile(userId);
        return buildResponse(HttpStatus.OK, "Profile retrieved successfully", profile);
    }

    //UPDATE PROFILE
    @PutMapping(value = "/my-profile", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> updateMyProfile(
            @RequestHeader("Authorization") String authHeader,

            @Valid @ModelAttribute UserProfileUpdateRequest dto,

            @RequestParam(value = "avatar", required = false) MultipartFile avatarFile
    ) throws IOException { // Thêm throws IOException

        Long userId = getUserIdFromToken(authHeader);

        UserProfileResponse updatedProfile = profileService.updateProfile(userId, dto, avatarFile);

        return buildResponse(HttpStatus.OK, "Profile updated successfully", updatedProfile);
    }

    //Get All Users
    @GetMapping("/admin/users")
    public ResponseEntity<Map<String, Object>> getAllUsers(
            @RequestParam(required = false) String role
    ) {
        List<UserProfileResponse> users = profileService.getAllUsers(role);

        String message = (role != null)
                ? "List of " + role + " retrieved successfully"
                : "All users (User & Admin) retrieved successfully";

        return buildResponse(HttpStatus.OK, message, users);
    }

    //Update Status
    @PutMapping("/admin/{id}/status")
    public ResponseEntity<Map<String, Object>> updateStatus(
            @PathVariable Long id,
            @RequestParam String status) {

        UserProfileResponse updatedUser = profileService.updateUserStatus(id, status);
        return buildResponse(HttpStatus.OK, "User status updated successfully", updatedUser);
    }

    //Delete User
    @DeleteMapping("/admin/{id}")
    public ResponseEntity<Map<String, Object>> deleteUser(@PathVariable Long id) {
        profileService.deleteUser(id);
        return buildResponse(HttpStatus.OK, "User deleted successfully", null);
    }
}