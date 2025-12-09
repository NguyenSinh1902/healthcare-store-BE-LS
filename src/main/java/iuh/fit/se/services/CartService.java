package iuh.fit.se.services;

import iuh.fit.se.dtos.cart.CartResponseDTO;
import iuh.fit.se.dtos.cartitem.CartItemRequestDTO;
import iuh.fit.se.dtos.cartitem.CartItemResponseDTO;

public interface CartService {

    // Lấy giỏ hàng
    CartResponseDTO getCartByUser(Long userId);

    // Thêm vào giỏ
    CartItemResponseDTO addItemToCart(Long userId, CartItemRequestDTO requestDTO);

    // Cập nhật số lượng (Cần userId để check chủ sở hữu)
    CartItemResponseDTO updateItemQuantity(Long userId, Long cartItemId, Integer newQuantity);

    // Xóa 1 món (Cần userId để check chủ sở hữu)
    void removeItemFromCart(Long userId, Long cartItemId);

    // Xóa sạch giỏ
    void clearCartByUser(Long userId);
}