package iuh.fit.se.services;

import iuh.fit.se.dtos.product.ProductRequestDTO;
import iuh.fit.se.dtos.product.ProductResponseDTO;
import iuh.fit.se.dtos.product.ProductDetailDTO;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

public interface ProductService {

    //Get all products by group (for homepage)
    List<ProductResponseDTO> getProductsByGroup(String productGroup);

    //Get all products by category
    List<ProductResponseDTO> getProductsByCategory(Long categoryId);

    //Get product details by ID
    ProductDetailDTO getProductDetail(Long id);


    //ADMIN

    //Get All product
    List<ProductResponseDTO> getAllProducts();

    // Sửa dòng này trong Interface
    // Thêm tham số MultipartFile imageFile
    ProductResponseDTO createProduct(ProductRequestDTO dto, MultipartFile imageFile, List<MultipartFile> thumbnailFiles) throws IOException;

    //Update product
    // Nếu muốn làm update ảnh luôn thì sửa dòng này:
    ProductResponseDTO updateProduct(Long id, ProductRequestDTO dto, MultipartFile imageFile, List<MultipartFile> thumbnailFiles) throws IOException;

    //Delete product
    void deleteProduct(Long id);

    //filter Products
    List<ProductResponseDTO> filterProducts(String brand, Double minPrice, Double maxPrice, Long categoryId, String sort);

    //Search keyword
    List<ProductResponseDTO> searchProducts(String keyword);
}
