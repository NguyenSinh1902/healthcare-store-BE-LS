package iuh.fit.se.dtos.cart;

import jakarta.validation.constraints.NotNull;

public class CartRequestDTO {

    @NotNull(message = "User ID is required")
    private Long idUser;

    private Double totalAmount = 0.0;

    public CartRequestDTO() {
    }

    public CartRequestDTO(Long idUser, Double totalAmount) {
        this.idUser = idUser;
        this.totalAmount = totalAmount;
    }

    public Long getIdUser() {
        return idUser;
    }

    public void setIdUser(Long idUser) {
        this.idUser = idUser;
    }

    public Double getTotalAmount() {
        return totalAmount;
    }

    public void setTotalAmount(Double totalAmount) {
        this.totalAmount = totalAmount;
    }
}
