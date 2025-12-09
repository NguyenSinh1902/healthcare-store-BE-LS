package iuh.fit.se.controllers;

import iuh.fit.se.dtos.category.CategoryRequestDTO;
import iuh.fit.se.dtos.category.CategoryResponseDTO;
import iuh.fit.se.services.CategoryService;
import jakarta.validation.Valid; // Nhớ import Valid
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType; // Import MediaType
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile; // Import MultipartFile

import java.io.IOException;
import java.util.*;

@RestController
@RequestMapping("/api/categories")
@CrossOrigin(origins = "*")
public class CategoryController {

    private final CategoryService categoryService;

    public CategoryController(CategoryService categoryService) {
        this.categoryService = categoryService;
    }

    @GetMapping("/parents")
    public ResponseEntity<Map<String, Object>> getParentCategories() {
        List<CategoryResponseDTO> parentCategories = categoryService.getParentCategories();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "List of parent categories retrieved successfully");
        body.put("data", parentCategories);
        return ResponseEntity.ok(body);
    }

    @GetMapping("/{parentId}/subcategories")
    public ResponseEntity<Map<String, Object>> getSubCategories(@PathVariable Long parentId) {
        List<CategoryResponseDTO> subCategories = categoryService.getSubCategories(parentId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Subcategories retrieved successfully for parent ID: " + parentId);
        body.put("data", subCategories);
        return ResponseEntity.ok(body);
    }

    // --- CREATE
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> createCategory(
            @Valid @ModelAttribute CategoryRequestDTO dto, // Thay @RequestBody bằng @ModelAttribute
            @RequestParam(value = "image", required = false) MultipartFile imageFile // Thêm file
    ) throws IOException {

        CategoryResponseDTO response = categoryService.createCategory(dto, imageFile);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Category created successfully");
        body.put("data", response);

        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    //UPDATE
    @PutMapping(value = "/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> updateCategory(
            @PathVariable Long id,
            @ModelAttribute CategoryRequestDTO dto, // Thay @RequestBody bằng @ModelAttribute
            @RequestParam(value = "image", required = false) MultipartFile imageFile
    ) throws IOException {

        CategoryResponseDTO updatedCategory = categoryService.updateCategory(id, dto, imageFile);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Category updated successfully (ID: " + id + ")");
        body.put("data", updatedCategory);

        return ResponseEntity.ok(body);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> deleteCategory(@PathVariable Long id) {
        categoryService.deleteCategory(id);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Category deleted successfully (ID: " + id + ")");
        body.put("data", null);
        return ResponseEntity.ok(body);
    }

    // Get ALL categories
    @GetMapping
    public ResponseEntity<Map<String, Object>> getAllCategories() {
        List<CategoryResponseDTO> categories = categoryService.getAllCategories();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "All categories retrieved successfully");
        body.put("data", categories);

        return ResponseEntity.ok(body);
    }
}