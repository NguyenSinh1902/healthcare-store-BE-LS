//package iuh.fit.se.controllers;
//
//import iuh.fit.se.dtos.cartitem.CartItemRequestDTO;
//import iuh.fit.se.dtos.cartitem.CartItemResponseDTO;
//import iuh.fit.se.services.CartItemService;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.LinkedHashMap;
//import java.util.List;
//import java.util.Map;
//
//@RestController
//@RequestMapping("/api/cart-items")
//@CrossOrigin(origins = "*")
//public class CartItemController {
//
//    private final CartItemService cartItemService;
//
//    public CartItemController(CartItemService cartItemService) {
//        this.cartItemService = cartItemService;
//    }
//
//    //Get all items in a cart
//    @GetMapping("/cart/{cartId}")
//    public ResponseEntity<Map<String, Object>> getItemsByCart(@PathVariable Long cartId) {
//        List<CartItemResponseDTO> items = cartItemService.getItemsByCartId(cartId);
//
//        Map<String, Object> body = new LinkedHashMap<>();
//        body.put("success", true);
//        body.put("message", "Cart items retrieved successfully");
//        body.put("data", items);
//
//        return ResponseEntity.ok(body);
//    }
//
//    //Get single item
//    @GetMapping("/{id}")
//    public ResponseEntity<Map<String, Object>> getCartItem(@PathVariable Long id) {
//        CartItemResponseDTO item = cartItemService.getItemById(id);
//
//        Map<String, Object> body = new LinkedHashMap<>();
//        body.put("success", true);
//        body.put("message", "Cart item retrieved successfully");
//        body.put("data", item);
//
//        return ResponseEntity.ok(body);
//    }
//
//    //Add new cart item
//    @PostMapping
//    public ResponseEntity<Map<String, Object>> addCartItem(@RequestBody CartItemRequestDTO dto) {
//        CartItemResponseDTO created = cartItemService.addCartItem(dto);
//
//        Map<String, Object> body = new LinkedHashMap<>();
//        body.put("success", true);
//        body.put("message", "Cart item added successfully");
//        body.put("data", created);
//
//        return ResponseEntity.status(HttpStatus.CREATED).body(body);
//    }
//
//    //Update quantity
//    @PutMapping("/{id}")
//    public ResponseEntity<Map<String, Object>> updateQuantity(
//            @PathVariable Long id,
//            @RequestParam Integer quantity) {
//
//        CartItemResponseDTO updated = cartItemService.updateCartItem(id, quantity);
//
//        Map<String, Object> body = new LinkedHashMap<>();
//        body.put("success", true);
//        body.put("message", "Cart item quantity updated successfully");
//        body.put("data", updated);
//
//        return ResponseEntity.ok(body);
//    }
//
//    //Delete item
//    @DeleteMapping("/{id}")
//    public ResponseEntity<Map<String, Object>> deleteCartItem(@PathVariable Long id) {
//        cartItemService.deleteCartItem(id);
//
//        Map<String, Object> body = new LinkedHashMap<>();
//        body.put("success", true);
//        body.put("message", "Cart item deleted successfully");
//
//        return ResponseEntity.ok(body);
//    }
//}
