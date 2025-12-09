package iuh.fit.se.dtos.category;

public class CategoryResponseDTO {

    private Long idCategory;
    private String nameCategory;
    private String description;
    private String imageCategory;
    private Long parentCategoryId; //id of parent category (if any)

    public CategoryResponseDTO() {
    }

    public CategoryResponseDTO(Long idCategory, String nameCategory, String description, String imageCategory, Long parentCategoryId) {
        this.idCategory = idCategory;
        this.nameCategory = nameCategory;
        this.description = description;
        this.imageCategory = imageCategory;
        this.parentCategoryId = parentCategoryId;
    }

    // Getters & Setters
    public Long getIdCategory() {
        return idCategory;
    }

    public void setIdCategory(Long idCategory) {
        this.idCategory = idCategory;
    }

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
