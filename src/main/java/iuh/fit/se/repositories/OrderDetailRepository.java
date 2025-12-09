package iuh.fit.se.repositories;

import iuh.fit.se.dtos.dashboard.ChartDataDTO;
import iuh.fit.se.dtos.dashboard.TopProductDTO;
import iuh.fit.se.entities.order.OrderDetail;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OrderDetailRepository extends JpaRepository<OrderDetail, Long> {

    //Top sản phẩm bán chạy
    @Query("SELECT new iuh.fit.se.dtos.dashboard.TopProductDTO(" +
            "od.product.nameProduct, " +
            "SUM(od.quantity), " +
            "od.product.price, " +
            "od.product.imageProduct) " +
            "FROM OrderDetail od " +
            "GROUP BY od.product.idProduct, od.product.nameProduct, od.product.price, od.product.imageProduct " +
            "ORDER BY SUM(od.quantity) DESC")
    List<TopProductDTO> findTopSellingProducts(Pageable pageable);

    //Thống kê doanh thu theo Category
    @Query("SELECT new iuh.fit.se.dtos.dashboard.ChartDataDTO(" +
            "od.product.category.nameCategory, " +
            "SUM(od.totalPrice)) " +
            "FROM OrderDetail od " +
            "GROUP BY od.product.category.idCategory, od.product.category.nameCategory")
    List<ChartDataDTO> getCategorySalesDistribution();
}