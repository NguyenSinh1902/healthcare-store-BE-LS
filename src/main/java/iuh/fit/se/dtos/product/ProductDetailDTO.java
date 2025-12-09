package iuh.fit.se.dtos.product;

import java.util.List;

public class ProductDetailDTO {
    private Long idProduct;
    private String nameProduct;
    private String brand;
    private Double price;
    private Double oldPrice;
    private Integer discountPercent;
    private Integer stockQuantity;
    private String imageProduct;
    private String description;
    private String information;
    private String productGroup;
    private Long idCategory;
    private String categoryName;
    // DANH SÁCH ẢNH THUMBNAIL
    private List<String> thumbnails;

    public ProductDetailDTO() {
    }

    public ProductDetailDTO(Long idProduct, String nameProduct, String brand, Double price, Double oldPrice, Integer discountPercent, Integer stockQuantity, String imageProduct, String description, String information, String productGroup, Long idCategory, String categoryName, List<String> thumbnails) {
        this.idProduct = idProduct;
        this.nameProduct = nameProduct;
        this.brand = brand;
        this.price = price;
        this.oldPrice = oldPrice;
        this.discountPercent = discountPercent;
        this.stockQuantity = stockQuantity;
        this.imageProduct = imageProduct;
        this.description = description;
        this.information = information;
        this.productGroup = productGroup;
        this.idCategory = idCategory;
        this.categoryName = categoryName;
        this.thumbnails = thumbnails;
    }

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

    public String getImageProduct() {
        return imageProduct;
    }

    public void setImageProduct(String imageProduct) {
        this.imageProduct = imageProduct;
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

    public String getProductGroup() {
        return productGroup;
    }

    public void setProductGroup(String productGroup) {
        this.productGroup = productGroup;
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

    public List<String> getThumbnails() {
        return thumbnails;
    }

    public void setThumbnails(List<String> thumbnails) {
        this.thumbnails = thumbnails;
    }
}
