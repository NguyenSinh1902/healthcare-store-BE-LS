package iuh.fit.se.controllers;

import iuh.fit.se.services.impl.DashboardServiceImpl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/dashboard")
@CrossOrigin(origins = "*")
public class DashboardController {

    private final DashboardServiceImpl dashboardService;

    public DashboardController(DashboardServiceImpl dashboardService) {
        this.dashboardService = dashboardService;
    }

    // Hàm Helper để tạo response
    private ResponseEntity<Map<String, Object>> buildResponse(Object data) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("message", "Data retrieved successfully");
        response.put("data", data);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getDashboardStats() {
        return buildResponse(dashboardService.getStats());
    }

    @GetMapping("/trend")
    public ResponseEntity<Map<String, Object>> getMonthlyTrend() {
        return buildResponse(dashboardService.getMonthlyTrend());
    }

    @GetMapping("/top-products")
    public ResponseEntity<Map<String, Object>> getTopProducts() {
        return buildResponse(dashboardService.getTopSellingProducts());
    }

    @GetMapping("/category-distribution")
    public ResponseEntity<Map<String, Object>> getCategoryDistribution() {
        return buildResponse(dashboardService.getCategoryDistribution());
    }

    @GetMapping("/recent-orders")
    public ResponseEntity<Map<String, Object>> getRecentOrders() {
        return buildResponse(dashboardService.getRecentOrders());
    }
}