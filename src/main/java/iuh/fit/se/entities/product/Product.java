package iuh.fit.se.entities.product;

import iuh.fit.se.entities.category.Category;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import java.util.List;

@Entity
@Table(name = "products")
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idProduct;

    @NotBlank(message = "Product name is required")
    @Size(min = 3, max = 150, message = "Product name must be between 3 and 150 characters")
    @Column(nullable = false)
    private String nameProduct;

    @NotBlank(message = "Brand is required")
    @Size(min = 2, max = 100, message = "Brand name must be between 2 and 100 characters")
    @Column(nullable = false)
    private String brand;

    @NotNull(message = "Price is required")
    @Positive(message = "Price must be greater than 0")
    @Column(nullable = false)
    private Double price;

    @PositiveOrZero(message = "Old price must be greater or equal to 0")
    private Double oldPrice;

    @Min(value = 0, message = "Discount must be between 0 and 100")
    @Max(value = 100, message = "Discount must be between 0 and 100")
    private Integer discountPercent;

    @NotNull(message = "Stock quantity is required")
    @PositiveOrZero(message = "Stock quantity cannot be negative")
    @Column(nullable = false)
    private Integer stockQuantity;

    @NotBlank(message = "Product image URL is required")
    @Pattern(
            regexp = ".*\\.(png|jpg|jpeg)$",
            message = "Image URL must be valid (.jpg, .png, .jpeg)"
    )
    @Column(nullable = false)
    private String imageProduct;

    // ⭐ DANH SÁCH NHIỀU THUMBNAIL
    @ElementCollection
    @CollectionTable(name="product_thumbnails", joinColumns=@JoinColumn(name="product_id"))
    @Column(name="thumbnail_url")
    private List<String> thumbnails;


    @NotBlank(message = "Product description is required")
    @Size(min = 10, message = "Description must be at least 10 characters long")
    @Column(columnDefinition = "TEXT")
    private String description;

    @Size(max = 1000, message = "Information must not exceed 1000 characters")
    @Column(columnDefinition = "TEXT")
    private String information;

    // N Product -> 1 Category
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "id_category", referencedColumnName = "id_category", nullable = false)
    @NotNull(message = "Category is required")
    private Category category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ProductGroup productGroup = ProductGroup.NORMAL;

    // 👇 THÊM FIELD NÀY VÀO
    @Column(name = "is_active")
    private boolean active = true; // Mặc định là true (Đang hoạt động/Đang bán)

    public Product() {}

    public Product(Long idProduct, String nameProduct, String brand, Double price, Double oldPrice, Integer discountPercent, Integer stockQuantity, String imageProduct, List<String> thumbnails, String description, String information, Category category, ProductGroup productGroup, boolean active) {
        this.idProduct = idProduct;
        this.nameProduct = nameProduct;
        this.brand = brand;
        this.price = price;
        this.oldPrice = oldPrice;
        this.discountPercent = discountPercent;
        this.stockQuantity = stockQuantity;
        this.imageProduct = imageProduct;
        this.thumbnails = thumbnails;
        this.description = description;
        this.information = information;
        this.category = category;
        this.productGroup = productGroup;
        this.active = active;
    }

    public Long getIdProduct() {
        return idProduct;
    }

    public void setIdProduct(Long idProduct) {
        this.idProduct = idProduct;
    }

    public @NotBlank(message = "Product name is required") @Size(min = 3, max = 150, message = "Product name must be between 3 and 150 characters") String getNameProduct() {
        return nameProduct;
    }

    public void setNameProduct(@NotBlank(message = "Product name is required") @Size(min = 3, max = 150, message = "Product name must be between 3 and 150 characters") String nameProduct) {
        this.nameProduct = nameProduct;
    }

    public @NotBlank(message = "Brand is required") @Size(min = 2, max = 100, message = "Brand name must be between 2 and 100 characters") String getBrand() {
        return brand;
    }

    public void setBrand(@NotBlank(message = "Brand is required") @Size(min = 2, max = 100, message = "Brand name must be between 2 and 100 characters") String brand) {
        this.brand = brand;
    }

    public @NotNull(message = "Price is required") @Positive(message = "Price must be greater than 0") Double getPrice() {
        return price;
    }

    public void setPrice(@NotNull(message = "Price is required") @Positive(message = "Price must be greater than 0") Double price) {
        this.price = price;
    }

    public @PositiveOrZero(message = "Old price must be greater or equal to 0") Double getOldPrice() {
        return oldPrice;
    }

    public void setOldPrice(@PositiveOrZero(message = "Old price must be greater or equal to 0") Double oldPrice) {
        this.oldPrice = oldPrice;
    }

    public @Min(value = 0, message = "Discount must be between 0 and 100") @Max(value = 100, message = "Discount must be between 0 and 100") Integer getDiscountPercent() {
        return discountPercent;
    }

    public void setDiscountPercent(@Min(value = 0, message = "Discount must be between 0 and 100") @Max(value = 100, message = "Discount must be between 0 and 100") Integer discountPercent) {
        this.discountPercent = discountPercent;
    }

    public @NotNull(message = "Stock quantity is required") @PositiveOrZero(message = "Stock quantity cannot be negative") Integer getStockQuantity() {
        return stockQuantity;
    }

    public void setStockQuantity(@NotNull(message = "Stock quantity is required") @PositiveOrZero(message = "Stock quantity cannot be negative") Integer stockQuantity) {
        this.stockQuantity = stockQuantity;
    }

    public @NotBlank(message = "Product image URL is required") @Pattern(
            regexp = ".*\\.(png|jpg|jpeg)$",
            message = "Image URL must be valid (.jpg, .png, .jpeg)"
    ) String getImageProduct() {
        return imageProduct;
    }

    public void setImageProduct(@NotBlank(message = "Product image URL is required") @Pattern(
            regexp = ".*\\.(png|jpg|jpeg)$",
            message = "Image URL must be valid (.jpg, .png, .jpeg)"
    ) String imageProduct) {
        this.imageProduct = imageProduct;
    }

    public List<String> getThumbnails() {
        return thumbnails;
    }

    public void setThumbnails(List<String> thumbnails) {
        this.thumbnails = thumbnails;
    }

    public @NotBlank(message = "Product description is required") @Size(min = 10, message = "Description must be at least 10 characters long") String getDescription() {
        return description;
    }

    public void setDescription(@NotBlank(message = "Product description is required") @Size(min = 10, message = "Description must be at least 10 characters long") String description) {
        this.description = description;
    }

    public @Size(max = 1000, message = "Information must not exceed 1000 characters") String getInformation() {
        return information;
    }

    public void setInformation(@Size(max = 1000, message = "Information must not exceed 1000 characters") String information) {
        this.information = information;
    }

    public @NotNull(message = "Category is required") Category getCategory() {
        return category;
    }

    public void setCategory(@NotNull(message = "Category is required") Category category) {
        this.category = category;
    }

    public ProductGroup getProductGroup() {
        return productGroup;
    }

    public void setProductGroup(ProductGroup productGroup) {
        this.productGroup = productGroup;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}
