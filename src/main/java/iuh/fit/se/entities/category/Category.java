package iuh.fit.se.entities.category;

import iuh.fit.se.entities.product.Product;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "categories")
//@JsonIgnoreProperties({"products"}) // tranh vong lap JSON khi tra ve
public class Category {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_category")
    private Long idCategory;

    @NotBlank(message = "Category name is required")
    @Size(min = 3, max = 100, message = "Category name must be between 3 and 100 characters")
    @Column(unique = true, nullable = false)
    private String nameCategory;

    @Size(max = 255, message = "Description must be less than 255 characters")
    private String description;

    @Pattern(
            regexp = "^(https?:\\/\\/.*\\.(?:png|jpg|jpeg))?$",
            message = "Image URL must be valid (.jpg, .png, .jpeg)"
    )
    private String imageCategory;

    @Column(name = "parent_category_id")
    private Long parentCategoryId; // null = cha, khac null = con cua ID đo

    @OneToMany(mappedBy = "category", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private Set<Product> products = new HashSet<>();

    public Category() {}

    public Category(Long idCategory, String nameCategory, String description, String imageCategory, Long parentCategoryId, Set<Product> products) {
        this.idCategory = idCategory;
        this.nameCategory = nameCategory;
        this.description = description;
        this.imageCategory = imageCategory;
        this.parentCategoryId = parentCategoryId;
        this.products = products;
    }

    // getters/setters

    public Long getIdCategory() {
        return idCategory;
    }

    public void setIdCategory(Long idCategory) {
        this.idCategory = idCategory;
    }

    public @NotBlank(message = "Category name is required") @Size(min = 3, max = 100, message = "Category name must be between 3 and 100 characters") String getNameCategory() {
        return nameCategory;
    }

    public void setNameCategory(@NotBlank(message = "Category name is required") @Size(min = 3, max = 100, message = "Category name must be between 3 and 100 characters") String nameCategory) {
        this.nameCategory = nameCategory;
    }

    public @Size(max = 255, message = "Description must be less than 255 characters") String getDescription() {
        return description;
    }

    public void setDescription(@Size(max = 255, message = "Description must be less than 255 characters") String description) {
        this.description = description;
    }

    public @Pattern(
            regexp = "^(https?:\\/\\/.*\\.(?:png|jpg|jpeg))?$",
            message = "Image URL must be valid (.jpg, .png, .jpeg)"
    ) String getImageCategory() {
        return imageCategory;
    }

    public void setImageCategory(@Pattern(
            regexp = "^(https?:\\/\\/.*\\.(?:png|jpg|jpeg))?$",
            message = "Image URL must be valid (.jpg, .png, .jpeg)"
    ) String imageCategory) {
        this.imageCategory = imageCategory;
    }

    public Long getParentCategoryId() {
        return parentCategoryId;
    }

    public void setParentCategoryId(Long parentCategoryId) {
        this.parentCategoryId = parentCategoryId;
    }

    public Set<Product> getProducts() {
        return products;
    }

    public void setProducts(Set<Product> products) {
        this.products = products;
    }
}
