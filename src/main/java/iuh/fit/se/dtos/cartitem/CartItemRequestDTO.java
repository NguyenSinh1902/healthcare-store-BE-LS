package iuh.fit.se.dtos.cartitem;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public class CartItemRequestDTO {

    @NotNull(message = "Product ID is required")
    private Long idProduct;

    @NotNull(message = "Quantity is required")
    @Positive(message = "Quantity must be greater than 0")
    private Integer quantity;

    public CartItemRequestDTO() {
    }

    public CartItemRequestDTO(Long idProduct, Integer quantity) {
        this.idProduct = idProduct;
        this.quantity = quantity;
    }

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
}

