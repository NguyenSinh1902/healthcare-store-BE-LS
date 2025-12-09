package iuh.fit.se.dtos.category;

import jakarta.validation.constraints.*;

public class CategoryRequestDTO {

    @NotBlank(message = "Category name is required")
    @Size(min = 3, max = 100, message = "Category name must be between 3 and 100 characters")
    private String nameCategory;

    @Size(max = 255, message = "Description must be less than 255 characters")
    private String description;

    @Pattern(
            regexp = "^(https?:\\/\\/.*\\.(?:png|jpg|jpeg))?$",
            message = "Image URL must be valid (.jpg, .png, .jpeg)"
    )
    private String imageCategory;

    private Long parentCategoryId; // null = cha, khac null = con

    public CategoryRequestDTO() {
    }

    public CategoryRequestDTO(String nameCategory, String description, String imageCategory, Long parentCategoryId) {
        this.nameCategory = nameCategory;
        this.description = description;
        this.imageCategory = imageCategory;
        this.parentCategoryId = parentCategoryId;
    }

    // Getters & Setters
    public String getNameCategory() {
        return nameCategory;
    }

    public void setNameCategory(String nameCategory) {
        this.nameCategory = nameCategory;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getImageCategory() {
        return imageCategory;
    }

    public void setImageCategory(String imageCategory) {
        this.imageCategory = imageCategory;
    }

    public Long getParentCategoryId() {
        return parentCategoryId;
    }

    public void setParentCategoryId(Long parentCategoryId) {
        this.parentCategoryId = parentCategoryId;
    }
}
