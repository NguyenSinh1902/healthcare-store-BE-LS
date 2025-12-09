package iuh.fit.se.dtos.cart;


import iuh.fit.se.dtos.cartitem.CartItemResponseDTO;

import java.util.List;

public class CartResponseDTO {
    private Long idCart;
    private Double totalAmount;
    private Long idUser;
    private List<CartItemResponseDTO> items;

    public CartResponseDTO() {
    }

    public CartResponseDTO(Long idCart, Double totalAmount, Long idUser, List<CartItemResponseDTO> items) {
        this.idCart = idCart;
        this.totalAmount = totalAmount;
        this.idUser = idUser;
        this.items = items;
    }

    public Long getIdCart() {
        return idCart;
    }

    public void setIdCart(Long idCart) {
        this.idCart = idCart;
    }

    public Double getTotalAmount() {
        return totalAmount;
    }

    public void setTotalAmount(Double totalAmount) {
        this.totalAmount = totalAmount;
    }

    public Long getIdUser() {
        return idUser;
    }

    public void setIdUser(Long idUser) {
        this.idUser = idUser;
    }

    public List<CartItemResponseDTO> getItems() {
        return items;
    }

    public void setItems(List<CartItemResponseDTO> items) {
        this.items = items;
    }
}
