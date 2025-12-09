package iuh.fit.se.mappers;

import iuh.fit.se.dtos.profile.*;
import iuh.fit.se.entities.auth.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserProfileMapper {
    UserProfileResponse toResponseDTO(User user);
}
