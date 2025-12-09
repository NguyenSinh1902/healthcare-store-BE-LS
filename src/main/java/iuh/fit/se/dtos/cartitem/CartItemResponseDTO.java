package iuh.fit.se.dtos.cartitem;

public class CartItemResponseDTO {
    private Long idCartItem;
    private Long idProduct;
    private String nameProduct;
    private String imageProduct;
    private Double unitPrice;
    private Integer quantity;
    private Double totalPrice;

    private boolean active;

    public CartItemResponseDTO() {
    }

    public CartItemResponseDTO(Long idCartItem, Long idProduct, String nameProduct, String imageProduct, Double unitPrice, Integer quantity, Double totalPrice, boolean active) {
        this.idCartItem = idCartItem;
        this.idProduct = idProduct;
        this.nameProduct = nameProduct;
        this.imageProduct = imageProduct;
        this.unitPrice = unitPrice;
        this.quantity = quantity;
        this.totalPrice = totalPrice;
        this.active = active;
    }

    public Long getIdCartItem() {
        return idCartItem;
    }

    public void setIdCartItem(Long idCartItem) {
        this.idCartItem = idCartItem;
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

    public String getImageProduct() {
        return imageProduct;
    }

    public void setImageProduct(String imageProduct) {
        this.imageProduct = imageProduct;
    }

    public Double getUnitPrice() {
        return unitPrice;
    }

    public void setUnitPrice(Double unitPrice) {
        this.unitPrice = unitPrice;
    }

    public Integer getQuantity() {
        return quantity;
    }

    public void setQuantity(Integer quantity) {
        this.quantity = quantity;
    }

    public Double getTotalPrice() {
        return totalPrice;
    }

    public void setTotalPrice(Double totalPrice) {
        this.totalPrice = totalPrice;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}

