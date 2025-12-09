package iuh.fit.se.repositories;

import iuh.fit.se.entities.product.Product;
import iuh.fit.se.entities.product.ProductGroup;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {

    //Cho trang chủ (theo Group) -> Chỉ lấy Active
    List<Product> findByProductGroupAndActiveTrue(ProductGroup productGroup);

    //Cho trang danh mục (theo Category ID) -> Chỉ lấy Active
    List<Product> findByCategory_IdCategoryAndActiveTrue(Long categoryId);

    //Cho trang chi tiết (Detail)
    // Tìm theo ID nhưng phải Active. Nếu ID tồn tại mà Active=false thì cũng coi như không thấy.
    Optional<Product> findByIdProductAndActiveTrue(Long idProduct);

    //Find product by name
    Optional<Product> findByNameProduct(String nameProduct);

    //Filter products by price range and brand (if available)
    @Query("""
        SELECT p FROM Product p
        WHERE (:brand IS NULL OR p.brand = :brand)
        AND (:minPrice IS NULL OR p.price >= :minPrice)
        AND (:maxPrice IS NULL OR p.price <= :maxPrice)
        AND (:categoryId IS NULL OR p.category.idCategory = :categoryId)
        """)
    List<Product> filterProducts(
            @Param("brand") String brand,
            @Param("minPrice") Double minPrice,
            @Param("maxPrice") Double maxPrice,
            @Param("categoryId") Long categoryId,
            Sort sort
    );

    //Tìm sản phẩm có tên chứa từ khóa (không phân biệt hoa thường)
    List<Product> findByNameProductContainingIgnoreCase(String keyword);

    //Chỉ lấy sản phẩm đang hoạt động (active = true)
    List<Product> findByActiveTrue();

    long count();
}
