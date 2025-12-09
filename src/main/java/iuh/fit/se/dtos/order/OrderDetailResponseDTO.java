package iuh.fit.se.dtos.order;

public class OrderDetailResponseDTO {

    private Long idOrderDetail;
    private Long idProduct;
    private String productName;
    private Integer quantity;
    private Double unitPrice;
    private Double totalPrice;
    private String imageProduct;

    public OrderDetailResponseDTO() {}

    public OrderDetailResponseDTO(Long idOrderDetail, Long idProduct, String productName, Integer quantity, Double unitPrice, Double totalPrice, String imageProduct) {
        this.idOrderDetail = idOrderDetail;
        this.idProduct = idProduct;
        this.productName = productName;
        this.quantity = quantity;
        this.unitPrice = unitPrice;
        this.totalPrice = totalPrice;
        this.imageProduct = imageProduct;
    }

    // Getters và Setters

    public Long getIdOrderDetail() {
        return idOrderDetail;
    }

    public void setIdOrderDetail(Long idOrderDetail) {
        this.idOrderDetail = idOrderDetail;
    }

    public Long getIdProduct() {
        return idProduct;
    }

    public void setIdProduct(Long idProduct) {
        this.idProduct = idProduct;
    }

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public Integer getQuantity() {
        return quantity;
    }

    public void setQuantity(Integer quantity) {
        this.quantity = quantity;
    }

    public Double getUnitPrice() {
        return unitPrice;
    }

    public void setUnitPrice(Double unitPrice) {
        this.unitPrice = unitPrice;
    }

    public Double getTotalPrice() {
        return totalPrice;
    }

    public void setTotalPrice(Double totalPrice) {
        this.totalPrice = totalPrice;
    }

    public String getImageProduct() {
        return imageProduct;
    }

    public void setImageProduct(String imageProduct) {
        this.imageProduct = imageProduct;
    }
}
