package iuh.fit.se.controllers;

import iuh.fit.se.dtos.product.ProductRequestDTO;
import iuh.fit.se.dtos.product.ProductResponseDTO;
import iuh.fit.se.dtos.product.ProductDetailDTO;
import iuh.fit.se.services.ProductService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.*;

@RestController
@RequestMapping("/api/products")
@CrossOrigin(origins = "*")
public class ProductController {

    private final ProductService productService;

    public ProductController(ProductService productService) {
        this.productService = productService;
    }

    @GetMapping("/group/{group}")
    public ResponseEntity<Map<String, Object>> getProductsByGroup(@PathVariable String group) {
        List<ProductResponseDTO> products = productService.getProductsByGroup(group);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Products retrieved by group successfully");
        body.put("data", products);

        return ResponseEntity.ok(body);
    }


    //Get all products by category
    @GetMapping("/category/{categoryId}")
    public ResponseEntity<Map<String, Object>> getProductsByCategory(@PathVariable Long categoryId) {
        List<ProductResponseDTO> products = productService.getProductsByCategory(categoryId);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Products retrieved by category successfully");
        body.put("data", products);

        return ResponseEntity.ok(body);
    }

    //Get product detail by ID
    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> getProductDetail(@PathVariable Long id) {
        ProductDetailDTO detail = productService.getProductDetail(id);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Product detail retrieved successfully");
        body.put("data", detail);

        return ResponseEntity.ok(body);
    }

    // Filter products WITHIN a specific category
    // URL: /api/products/category/{categoryId}/filter?brand=...&minPrice=...
    @GetMapping("/category/{categoryId}/filter")
    public ResponseEntity<Map<String, Object>> filterProductsByCategory(
            @PathVariable Long categoryId,  // 👈 Lấy ID Category từ URL (Bắt buộc)
            @RequestParam(required = false) String brand,
            @RequestParam(required = false) Double minPrice,
            @RequestParam(required = false) Double maxPrice,
            @RequestParam(required = false, defaultValue = "featured") String sort
    ) {

        List<ProductResponseDTO> products = productService.filterProducts(brand, minPrice, maxPrice, categoryId, sort);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Filtered products within category " + categoryId + " successfully");

        Map<String, Object> activeFilters = new HashMap<>();
        activeFilters.put("categoryId", categoryId); // Luôn có
        if (brand != null) activeFilters.put("brand", brand);
        if (minPrice != null) activeFilters.put("minPrice", minPrice);
        if (maxPrice != null) activeFilters.put("maxPrice", maxPrice);
        activeFilters.put("sort", sort);

        body.put("filters", activeFilters);
        body.put("data", products);

        return ResponseEntity.ok(body);
    }


    //SEARCH
    @GetMapping("/search")
    public ResponseEntity<Map<String, Object>> searchProducts(@RequestParam String query) {
        List<ProductResponseDTO> products = productService.searchProducts(query);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Search results retrieved successfully");
        body.put("data", products);

        return ResponseEntity.ok(body);
    }

    // Get all products
    @GetMapping("/all")
    public ResponseEntity<Map<String, Object>> getAllProducts() {
        List<ProductResponseDTO> products = productService.getAllProducts();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "All products retrieved successfully");
        body.put("data", products);

        return ResponseEntity.ok(body);
    }

    //CREATE PRODUCT
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> createProduct(
            @Valid @ModelAttribute ProductRequestDTO dto,
            @RequestParam(value = "image", required = false) MultipartFile imageFile,

            @RequestParam(value = "thumbnailFiles", required = false) List<MultipartFile> thumbnailFiles
    ) throws IOException {

        ProductResponseDTO response = productService.createProduct(dto, imageFile, thumbnailFiles);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Product created successfully");
        body.put("data", response);

        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    //UPDATE PRODUCT
    @PutMapping(value = "/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> updateProduct(
            @PathVariable Long id,
            @ModelAttribute ProductRequestDTO dto,
            @RequestParam(value = "image", required = false) MultipartFile imageFile,

            @RequestParam(value = "thumbnailFiles", required = false) List<MultipartFile> thumbnailFiles
    ) throws IOException {

        ProductResponseDTO updated = productService.updateProduct(id, dto, imageFile, thumbnailFiles);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Product updated successfully");
        body.put("data", updated);

        return ResponseEntity.ok(body);
    }

    //Delete product
    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> deleteProduct(@PathVariable Long id) {
        productService.deleteProduct(id);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("message", "Product deleted successfully (ID: " + id + ")");

        return ResponseEntity.ok(body);
    }
}
