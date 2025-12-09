package iuh.fit.se.mappers;

import iuh.fit.se.dtos.category.CategoryRequestDTO;
import iuh.fit.se.dtos.category.CategoryResponseDTO;
import iuh.fit.se.entities.category.Category;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface CategoryMapper {
    Category toEntity(CategoryRequestDTO dto);
    CategoryResponseDTO toResponseDTO(Category entity);
}
