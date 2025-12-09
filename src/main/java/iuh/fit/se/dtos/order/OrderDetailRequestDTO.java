package iuh.fit.se.dtos.order;

import jakarta.validation.constraints.*;

public class OrderDetailRequestDTO {

    @NotNull(message = "Product ID is required")
    private Long idProduct;

    @NotNull(message = "Quantity is required")
    @Positive(message = "Quantity must be greater than 0")
    private Integer quantity;

    @NotNull(message = "Unit price is required")
    @Positive(message = "Unit price must be greater than 0")
    private Double unitPrice;

    @NotNull(message = "Total price is required")
    @PositiveOrZero(message = "Total price must be >= 0")
    private Double totalPrice;

    public OrderDetailRequestDTO() {}

    public OrderDetailRequestDTO(Long idProduct, Integer quantity, Double unitPrice, Double totalPrice) {
        this.idProduct = idProduct;
        this.quantity = quantity;
        this.unitPrice = unitPrice;
        this.totalPrice = totalPrice;
    }

    // Getters & Setters

    public @NotNull(message = "Product ID is required") Long getIdProduct() {
        return idProduct;
    }

    public void setIdProduct(@NotNull(message = "Product ID is required") Long idProduct) {
        this.idProduct = idProduct;
    }

    public @NotNull(message = "Quantity is required") @Positive(message = "Quantity must be greater than 0") Integer getQuantity() {
        return quantity;
    }

    public void setQuantity(@NotNull(message = "Quantity is required") @Positive(message = "Quantity must be greater than 0") Integer quantity) {
        this.quantity = quantity;
    }

    public @NotNull(message = "Unit price is required") @Positive(message = "Unit price must be greater than 0") Double getUnitPrice() {
        return unitPrice;
    }

    public void setUnitPrice(@NotNull(message = "Unit price is required") @Positive(message = "Unit price must be greater than 0") Double unitPrice) {
        this.unitPrice = unitPrice;
    }

    public @NotNull(message = "Total price is required") @PositiveOrZero(message = "Total price must be >= 0") Double getTotalPrice() {
        return totalPrice;
    }

    public void setTotalPrice(@NotNull(message = "Total price is required") @PositiveOrZero(message = "Total price must be >= 0") Double totalPrice) {
        this.totalPrice = totalPrice;
    }
}
