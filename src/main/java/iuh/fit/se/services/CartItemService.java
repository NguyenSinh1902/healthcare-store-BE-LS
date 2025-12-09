package iuh.fit.se.services;

import iuh.fit.se.dtos.cartitem.CartItemRequestDTO;
import iuh.fit.se.dtos.cartitem.CartItemResponseDTO;

import java.util.List;

public interface CartItemService {

    //Get all items in 1 cart
    List<CartItemResponseDTO> getItemsByCartId(Long cartId);

    //Get details of 1 item
    CartItemResponseDTO getItemById(Long id);

    //Add new item to cart
    CartItemResponseDTO addCartItem(CartItemRequestDTO dto);

    //Update item quantity
    CartItemResponseDTO updateCartItem(Long id, Integer newQuantity);

    //Delete 1 item
    void deleteCartItem(Long id);
}
