package iuh.fit.se.services;

import iuh.fit.se.dtos.category.CategoryRequestDTO;
import iuh.fit.se.dtos.category.CategoryResponseDTO;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

public interface CategoryService {

    //Get all parent categories (parentCategoryId = NULL)
    List<CategoryResponseDTO> getParentCategories();

    //Get all child categories by parent category ID
    List<CategoryResponseDTO> getSubCategories(Long parentId);

    //Them MultipartFile
    CategoryResponseDTO createCategory(CategoryRequestDTO dto, MultipartFile imageFile) throws IOException;
    CategoryResponseDTO updateCategory(Long id, CategoryRequestDTO dto, MultipartFile imageFile) throws IOException;

    //Delete category (parent or sub)
    void deleteCategory(Long id);

    // Get ALL categories (For Admin)
    List<CategoryResponseDTO> getAllCategories();
}
