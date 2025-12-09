package iuh.fit.se.services.impl;

import iuh.fit.se.dtos.category.CategoryRequestDTO;
import iuh.fit.se.dtos.category.CategoryResponseDTO;
import iuh.fit.se.entities.category.Category;
import iuh.fit.se.exceptions.NotFoundException;
import iuh.fit.se.mappers.CategoryMapper;
import iuh.fit.se.repositories.CategoryRepository;
import iuh.fit.se.services.CategoryService;
import iuh.fit.se.services.CloudinaryService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CategoryServiceImpl implements CategoryService {

    private final CategoryRepository categoryRepository;
    private final CategoryMapper categoryMapper;

    //Khai báo CloudinaryService
    private final CloudinaryService cloudinaryService;

    public CategoryServiceImpl(CategoryRepository categoryRepository, CategoryMapper categoryMapper, CloudinaryService cloudinaryService) {
        this.categoryRepository = categoryRepository;
        this.categoryMapper = categoryMapper;
        this.cloudinaryService = cloudinaryService;
    }

    //Get parent
    @Override
    public List<CategoryResponseDTO> getParentCategories() {
        List<Category> parents = categoryRepository.findByParentCategoryIdIsNull();
        if (parents.isEmpty()) {
            throw new NotFoundException("No parent directory was found.");
        }
        return parents.stream()
                .map(categoryMapper::toResponseDTO)
                .collect(Collectors.toList());
    }

    //Get child category by parent ID
    @Override
    public List<CategoryResponseDTO> getSubCategories(Long parentId) {
        List<Category> subs = categoryRepository.findByParentCategoryId(parentId);
        if (subs.isEmpty()) {
            throw new NotFoundException("No child category for parent ID: " + parentId);
        }
        return subs.stream()
                .map(categoryMapper::toResponseDTO)
                .collect(Collectors.toList());
    }

    //CREATE
    @Override
    public CategoryResponseDTO createCategory(CategoryRequestDTO dto, MultipartFile imageFile) throws IOException {

        if (imageFile != null && !imageFile.isEmpty()) {
            String imageUrl = cloudinaryService.uploadImage(imageFile);
            dto.setImageCategory(imageUrl);
        }

        Category category = categoryMapper.toEntity(dto);
        categoryRepository.save(category);
        return categoryMapper.toResponseDTO(category);
    }

    //delete
    @Transactional
    @Override
    public void deleteCategory(Long id) {
        Category category = categoryRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("No category found with ID: " + id));

        //Khi xoa danh muc cha => set các danh muc con ve NULL thay vi xoa luon
        List<Category> subCategories = categoryRepository.findByParentCategoryId(id);
        if (!subCategories.isEmpty()) {
            for (Category sub : subCategories) {
                sub.setParentCategoryId(null);
            }
            categoryRepository.saveAll(subCategories);
        }

        categoryRepository.delete(category);
    }

    //UPDATE CATEGORY
    @Transactional
    @Override
    public CategoryResponseDTO updateCategory(Long id, CategoryRequestDTO dto, MultipartFile imageFile) throws IOException {
        Category category = categoryRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Category not found with ID: " + id));

        if (imageFile != null && !imageFile.isEmpty()) {
            String imageUrl = cloudinaryService.uploadImage(imageFile);
            category.setImageCategory(imageUrl);
        }

        else if (dto.getImageCategory() != null) {
            category.setImageCategory(dto.getImageCategory());
        }

        if (dto.getNameCategory() != null) category.setNameCategory(dto.getNameCategory());
        if (dto.getDescription() != null) category.setDescription(dto.getDescription());

        category.setParentCategoryId(dto.getParentCategoryId());

        Category updated = categoryRepository.save(category);
        return categoryMapper.toResponseDTO(updated);
    }

    //GET ALL
    @Override
    public List<CategoryResponseDTO> getAllCategories() {
        List<Category> categories = categoryRepository.findAll();

        if (categories.isEmpty()) {
            throw new NotFoundException("No categories found");
        }

        return categories.stream()
                .map(categoryMapper::toResponseDTO)
                .collect(Collectors.toList());
    }
}
