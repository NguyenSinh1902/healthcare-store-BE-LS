package iuh.fit.se.controllers;

import iuh.fit.se.dtos.cart.CartResponseDTO;
import iuh.fit.se.dtos.cartitem.CartItemRequestDTO;
import iuh.fit.se.dtos.cartitem.CartItemResponseDTO;
import iuh.fit.se.services.CartService;
import iuh.fit.se.utils.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/cart")
@CrossOrigin(origins = "*")
public class CartController {

    private final CartService cartService;
    private final JwtUtil jwtUtil;

    public CartController(CartService cartService, JwtUtil jwtUtil) {
        this.cartService = cartService;
        this.jwtUtil = jwtUtil;
    }

    private Long getUserIdFromToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            return jwtUtil.extractUserId(token);
        }
        throw new RuntimeException("Invalid or missing Authorization header");
    }

    // GET My Cart
    @GetMapping("/my-cart")
    public ResponseEntity<Map<String, Object>> getMyCart(@RequestHeader("Authorization") String authHeader) {
        Long userId = getUserIdFromToken(authHeader);
        CartResponseDTO cart = cartService.getCartByUser(userId);
        return buildResponse(HttpStatus.OK, "Cart retrieved successfully", cart);
    }

    // ADD to Cart
    @PostMapping("/add")
    public ResponseEntity<Map<String, Object>> addToCart(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody CartItemRequestDTO dto) {
        Long userId = getUserIdFromToken(authHeader);
        CartItemResponseDTO addedItem = cartService.addItemToCart(userId, dto);
        return buildResponse(HttpStatus.CREATED, "Item added successfully", addedItem);
    }

    // UPDATE Quantity
    @PutMapping("/item/{itemId}")
    public ResponseEntity<Map<String, Object>> updateCartItem(
            @RequestHeader("Authorization") String authHeader,
            @PathVariable Long itemId,
            @RequestParam Integer quantity) {

        Long userId = getUserIdFromToken(authHeader);
        CartItemResponseDTO updated = cartService.updateItemQuantity(userId, itemId, quantity);

        return buildResponse(HttpStatus.OK, "Item updated successfully", updated);
    }

    // DELETE One Item
    @DeleteMapping("/item/{itemId}")
    public ResponseEntity<Map<String, Object>> removeItem(
            @RequestHeader("Authorization") String authHeader,
            @PathVariable Long itemId) {

        Long userId = getUserIdFromToken(authHeader);
        cartService.removeItemFromCart(userId, itemId);

        return buildResponse(HttpStatus.OK, "Item removed successfully", null);
    }

    // DELETE All (Clear Cart)
    @DeleteMapping("/clear")
    public ResponseEntity<Map<String, Object>> clearMyCart(@RequestHeader("Authorization") String authHeader) {
        Long userId = getUserIdFromToken(authHeader);
        cartService.clearCartByUser(userId);
        return buildResponse(HttpStatus.OK, "Cart cleared successfully", null);
    }

    // Helper tạo response cho gọn
    private ResponseEntity<Map<String, Object>> buildResponse(HttpStatus status, String message, Object data) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", message);
        if (data != null) {
            body.put("data", data);
        }
        return ResponseEntity.status(status).body(body);
    }
}