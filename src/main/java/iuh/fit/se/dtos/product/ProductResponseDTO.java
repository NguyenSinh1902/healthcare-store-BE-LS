package iuh.fit.se.dtos.product;

import java.util.List;

public class ProductResponseDTO {
    private Long idProduct;
    private String nameProduct;
    private String brand;
    private String imageProduct;
    private Double price;
    private Double oldPrice;
    private Integer discountPercent;
    private Integer stockQuantity;
    private String description;
    private String information;
    private Long idCategory;
    private String categoryName;
    private String productGroup;
    private List<String> thumbnails;

    private boolean active;

    public ProductResponseDTO() {
    }

    public ProductResponseDTO(Long idProduct, String nameProduct, String brand, String imageProduct, Double price, Double oldPrice, Integer discountPercent, Integer stockQuantity, String description, String information, Long idCategory, String categoryName, String productGroup, List<String> thumbnails, boolean active) {
        this.idProduct = idProduct;
        this.nameProduct = nameProduct;
        this.brand = brand;
        this.imageProduct = imageProduct;
        this.price = price;
        this.oldPrice = oldPrice;
        this.discountPercent = discountPercent;
        this.stockQuantity = stockQuantity;
        this.description = description;
        this.information = information;
        this.idCategory = idCategory;
        this.categoryName = categoryName;
        this.productGroup = productGroup;
        this.thumbnails = thumbnails;
        this.active = active;
    }

    // Getters and Setters


    public Long getIdProduct() {
        return idProduct;
    }

    public void setIdProduct(Long idProduct) {
        this.idProduct = idProduct;
    }

    public String getNameProduct() {
        return nameProduct;
    }

    public void setNameProduct(String nameProduct) {
        this.nameProduct = nameProduct;
    }

    public String getBrand() {
        return brand;
    }

    public void setBrand(String brand) {
        this.brand = brand;
    }

    public String getImageProduct() {
        return imageProduct;
    }

    public void setImageProduct(String imageProduct) {
        this.imageProduct = imageProduct;
    }

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
        this.price = price;
    }

    public Double getOldPrice() {
        return oldPrice;
    }

    public void setOldPrice(Double oldPrice) {
        this.oldPrice = oldPrice;
    }

    public Integer getDiscountPercent() {
        return discountPercent;
    }

    public void setDiscountPercent(Integer discountPercent) {
        this.discountPercent = discountPercent;
    }

    public Integer getStockQuantity() {
        return stockQuantity;
    }

    public void setStockQuantity(Integer stockQuantity) {
        this.stockQuantity = stockQuantity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getInformation() {
        return information;
    }

    public void setInformation(String information) {
        this.information = information;
    }

    public Long getIdCategory() {
        return idCategory;
    }

    public void setIdCategory(Long idCategory) {
        this.idCategory = idCategory;
    }

    public String getCategoryName() {
        return categoryName;
    }

    public void setCategoryName(String categoryName) {
        this.categoryName = categoryName;
    }

    public String getProductGroup() {
        return productGroup;
    }

    public void setProductGroup(String productGroup) {
        this.productGroup = productGroup;
    }

    public List<String> getThumbnails() {
        return thumbnails;
    }

    public void setThumbnails(List<String> thumbnails) {
        this.thumbnails = thumbnails;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}