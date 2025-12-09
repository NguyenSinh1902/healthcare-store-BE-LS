package iuh.fit.se.controllers;

import iuh.fit.se.dtos.order.OrderRequestDTO;
import iuh.fit.se.dtos.order.OrderResponseDTO;
import iuh.fit.se.entities.order.OrderStatus;
import iuh.fit.se.services.OrderService;
import iuh.fit.se.utils.JwtUtil;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/orders")
@CrossOrigin(origins = "*")
public class OrderController {

    private final OrderService orderService;
    private final JwtUtil jwtUtil;

    public OrderController(OrderService orderService, JwtUtil jwtUtil) {
        this.orderService = orderService;
        this.jwtUtil = jwtUtil;
    }

    private Long getUserIdFromToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            return jwtUtil.extractUserId(token);
        }
        throw new RuntimeException("Invalid or missing Authorization header");
    }

    //Checkout (Tạo đơn hàng từ giỏ)
    @PostMapping("/checkout")
    public ResponseEntity<Map<String, Object>> createOrderFromCart(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody OrderRequestDTO orderRequestDTO) {

        Long userId = getUserIdFromToken(authHeader);
        OrderResponseDTO orderResponse = orderService.createOrderFromCart(userId, orderRequestDTO);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Order created successfully");
        body.put("data", orderResponse);

        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    //Get My Orders
    @GetMapping("/my-orders")
    public ResponseEntity<Map<String, Object>> getMyOrders(@RequestHeader("Authorization") String authHeader) {
        Long userId = getUserIdFromToken(authHeader);
        List<OrderResponseDTO> orders = orderService.getOrdersByUser(userId);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "User orders retrieved successfully");
        body.put("data", orders);

        return ResponseEntity.ok(body);
    }

    //Get Order Details
    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> getOrderById(
            @RequestHeader("Authorization") String authHeader,
            @PathVariable Long id) {

        Long userId = getUserIdFromToken(authHeader);
        OrderResponseDTO order = orderService.getOrderById(id);

        if (!order.getIdUser().equals(userId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("success", false, "message", "You are not allowed to view this order"));
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Order details retrieved successfully");
        body.put("data", order);

        return ResponseEntity.ok(body);
    }

    //Get all orders (Admin)
    @GetMapping("/all")
    public ResponseEntity<Map<String, Object>> getAllOrders() {
        List<OrderResponseDTO> orders = orderService.getAllOrders();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "All orders retrieved successfully");
        body.put("data", orders);

        return ResponseEntity.ok(body);
    }

    //Update Status (Admin)
    @PutMapping("/{id}/status")
    public ResponseEntity<Map<String, Object>> updateOrderStatus(
            @PathVariable Long id,
            @RequestParam OrderStatus status) {

        OrderResponseDTO updatedOrder = orderService.updateOrderStatus(id, status);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Order status updated successfully");
        body.put("data", updatedOrder);

        return ResponseEntity.ok(body);
    }
}