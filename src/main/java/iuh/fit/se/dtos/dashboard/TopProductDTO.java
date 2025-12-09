package iuh.fit.se.dtos.dashboard;

public class TopProductDTO {
    private String productName;
    private Long soldQuantity;
    private Double price;
    private String image;

    public TopProductDTO(String productName, Long soldQuantity, Double price, String image) {
        this.productName = productName;
        this.soldQuantity = soldQuantity;
        this.price = price;
        this.image = image;
    }

    // Getters & Setters
    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public Long getSoldQuantity() {
        return soldQuantity;
    }

    public void setSoldQuantity(Long soldQuantity) {
        this.soldQuantity = soldQuantity;
    }

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
        this.price = price;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }
}