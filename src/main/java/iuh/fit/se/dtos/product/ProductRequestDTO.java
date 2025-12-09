package iuh.fit.se.dtos.product;

import jakarta.validation.constraints.*;
import java.util.List;

public class ProductRequestDTO {

    @NotBlank(message = "Product name is required")
    @Size(min = 3, max = 150, message = "Product name must be between 3 and 150 characters")
    private String nameProduct;

    @NotBlank(message = "Brand is required")
    @Size(min = 2, max = 100, message = "Brand name must be between 2 and 100 characters")
    private String brand;


    private Double price;

    @PositiveOrZero(message = "Old price must be greater or equal to 0")
    private Double oldPrice;

    @Min(value = 0, message = "Discount must be between 0 and 100")
    @Max(value = 100, message = "Discount must be between 0 and 100")
    private Integer discountPercent;

    @NotNull(message = "Stock quantity is required")
    @PositiveOrZero(message = "Stock quantity cannot be negative")
    private Integer stockQuantity;

    //@NotBlank(message = "Product image URL is required")
    @Pattern(
            regexp = ".*\\.(png|jpg|jpeg)$",
            message = "Image URL must be valid (.jpg, .png, .jpeg)"
    )
    private String imageProduct;

    //DANH SÁCH NHIỀU ẢNH THUMBNAIL
    private List<String> thumbnails;

    @NotBlank(message = "Product description is required")
    @Size(min = 10, message = "Description must be at least 10 characters long")
    private String description;

    @Size(max = 1000, message = "Information must not exceed 1000 characters")
    private String information;

    private Long idCategory;

    private String productGroup;

    public ProductRequestDTO() {
    }

    public ProductRequestDTO(String nameProduct, String brand, Double price, Double oldPrice, Integer discountPercent, Integer stockQuantity, String imageProduct, List<String> thumbnails, String description, String information, Long idCategory, String productGroup) {
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
        this.idCategory = idCategory;
        this.productGroup = productGroup;
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

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
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

    public @Pattern(
            regexp = ".*\\.(png|jpg|jpeg)$",
            message = "Image URL must be valid (.jpg, .png, .jpeg)"
    ) String getImageProduct() {
        return imageProduct;
    }

    public void setImageProduct(@Pattern(
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

    public Long getIdCategory() {
        return idCategory;
    }

    public void setIdCategory(Long idCategory) {
        this.idCategory = idCategory;
    }

    public String getProductGroup() {
        return productGroup;
    }

    public void setProductGroup(String productGroup) {
        this.productGroup = productGroup;
    }
}
