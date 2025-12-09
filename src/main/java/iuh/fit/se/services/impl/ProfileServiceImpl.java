package iuh.fit.se.services.impl;

import iuh.fit.se.dtos.profile.*;
import iuh.fit.se.entities.auth.Role;
import iuh.fit.se.entities.auth.User;
import iuh.fit.se.entities.auth.UserStatus;
import iuh.fit.se.mappers.UserProfileMapper;
import iuh.fit.se.repositories.UserRepository;
import iuh.fit.se.services.CloudinaryService;
import iuh.fit.se.services.ProfileService;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
public class ProfileServiceImpl implements ProfileService {

    private final UserRepository userRepository;
    private final UserProfileMapper mapper;

    private final CloudinaryService cloudinaryService;

    public ProfileServiceImpl(UserRepository userRepository, UserProfileMapper mapper, CloudinaryService cloudinaryService) {
        this.userRepository = userRepository;
        this.mapper = mapper;
        this.cloudinaryService = cloudinaryService;
    }

    @Override
    public UserProfileResponse getProfile(Long userId) {
        return userRepository.findById(userId)
                .map(mapper::toResponseDTO)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + userId));
    }

    @Override
    public UserProfileResponse updateProfile(Long userId, UserProfileUpdateRequest req, MultipartFile avatarFile) throws IOException {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        if (avatarFile != null && !avatarFile.isEmpty()) {
            String avatarUrl = cloudinaryService.uploadImage(avatarFile);
            user.setAvatarUrl(avatarUrl);
        }

        else if (req.getAvatarUrl() != null) {
            user.setAvatarUrl(req.getAvatarUrl());
        }

        if (req.getFullName() != null && !req.getFullName().isBlank()) {
            user.setFullName(req.getFullName());
        }
        if (req.getPhone() != null) {
            user.setPhone(req.getPhone());
        }
        if (req.getAddress() != null) {
            user.setAddress(req.getAddress());
        }
        if (req.getDateOfBirth() != null) {
            user.setDateOfBirth(req.getDateOfBirth());
        }

        return mapper.toResponseDTO(userRepository.save(user));
    }

    @Override
    public List<UserProfileResponse> getAllUsers(String role) {

        if (role == null || role.isEmpty()) {
            return userRepository.findByStatusNot(UserStatus.BANNED)
                    .stream()
                    .map(mapper::toResponseDTO)
                    .collect(Collectors.toList());
        }

        try {
            Role roleEnum = Role.valueOf(role.toUpperCase());
            return userRepository.findByRoleAndStatusNot(roleEnum, UserStatus.BANNED)
                    .stream()
                    .map(mapper::toResponseDTO)
                    .collect(Collectors.toList());
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid role: " + role);
        }
    }

    @Override
    public UserProfileResponse updateUserStatus(Long userId, String status) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        try {
            user.setStatus(UserStatus.valueOf(status.toUpperCase()));
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid status: " + status);
        }

        return mapper.toResponseDTO(userRepository.save(user));
    }

    @Override
    public void deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        user.setStatus(UserStatus.BANNED);

        userRepository.save(user);
    }
}