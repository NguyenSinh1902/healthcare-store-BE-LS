package iuh.fit.se.repositories;

import iuh.fit.se.dtos.dashboard.ChartDataDTO;
import iuh.fit.se.entities.order.Order;
import iuh.fit.se.entities.order.OrderStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {
    List<Order> findByUser_IdUser(Long userId);

    //Đếm tổng đơn hàng
    long count();

    //Tính tổng doanh thu (Chỉ tính đơn đã hoàn thành/thành công nếu có status)
    // Coi chừng null nếu chưa có đơn nào -> dùng COALESCE để trả về 0
    @Query("SELECT COALESCE(SUM(o.totalAmount), 0) FROM Order o WHERE o.status IN ('CONFIRMED', 'SHIPPING', 'DELIVERED')")
    Double sumTotalRevenue();

    // Thống kê Doanh thu và Số đơn theo THÁNG trong năm hiện tại
    @Query("SELECT new iuh.fit.se.dtos.dashboard.ChartDataDTO(" +
            "CAST(MONTH(o.orderDate) AS string), " +
            "SUM(o.totalAmount), " +
            "COUNT(o)) " +
            "FROM Order o " +
            "WHERE YEAR(o.orderDate) = YEAR(CURRENT_DATE) " +
            "AND o.status IN :statuses " +
            "GROUP BY MONTH(o.orderDate) " +
            "ORDER BY MONTH(o.orderDate)")
    List<ChartDataDTO> getMonthlyRevenue(@Param("statuses") List<OrderStatus> statuses);

    // Lấy 5 đơn hàng mới nhất
    List<Order> findTop5ByOrderByOrderDateDesc();
}
