package iuh.fit.se.services.impl;

import iuh.fit.se.dtos.dashboard.ChartDataDTO;
import iuh.fit.se.dtos.dashboard.DashboardStatsDTO;
import iuh.fit.se.dtos.dashboard.TopProductDTO;
import iuh.fit.se.dtos.order.OrderResponseDTO;
import iuh.fit.se.entities.auth.Role;
import iuh.fit.se.entities.order.OrderStatus;
import iuh.fit.se.mappers.OrderMapper;
import iuh.fit.se.repositories.*;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class DashboardServiceImpl {

    private final OrderRepository orderRepository;
    private final ProductRepository productRepository;
    private final UserRepository userRepository;

    private final OrderDetailRepository orderDetailRepository;
    private final OrderMapper orderMapper;

    public DashboardServiceImpl(OrderRepository orderRepository,
                                ProductRepository productRepository,
                                UserRepository userRepository,
                                OrderDetailRepository orderDetailRepository,
                                OrderMapper orderMapper) {
        this.orderRepository = orderRepository;
        this.productRepository = productRepository;
        this.userRepository = userRepository;
        this.orderDetailRepository = orderDetailRepository;
        this.orderMapper = orderMapper;
    }

    public DashboardStatsDTO getStats() {

        Double revenue = orderRepository.sumTotalRevenue();

        Long orders = orderRepository.count();

        Long products = productRepository.count();

        Long customers = userRepository.countByRole(Role.USER);

        return new DashboardStatsDTO(revenue, orders, products, customers);
    }


    // Biểu đồ Trend (Doanh thu & Đơn hàng theo tháng)
    public List<ChartDataDTO> getMonthlyTrend() {

        List<OrderStatus> validStatuses = Arrays.asList(
                OrderStatus.CONFIRMED, OrderStatus.SHIPPING, OrderStatus.DELIVERED
        );
        return orderRepository.getMonthlyRevenue(validStatuses);
    }

    // Top sản phẩm bán chạy (Bảng Top Selling)
    public List<TopProductDTO> getTopSellingProducts() {
        return orderDetailRepository.findTopSellingProducts(PageRequest.of(0, 5));
    }

    //(Pie Chart)
    public List<ChartDataDTO> getCategoryDistribution() {
        return orderDetailRepository.getCategorySalesDistribution();
    }

    //(Recent Orders)
    public List<OrderResponseDTO> getRecentOrders() {
        return orderRepository.findTop5ByOrderByOrderDateDesc()
                .stream()
                .map(orderMapper::toResponseDTO)
                .collect(Collectors.toList());
    }
}