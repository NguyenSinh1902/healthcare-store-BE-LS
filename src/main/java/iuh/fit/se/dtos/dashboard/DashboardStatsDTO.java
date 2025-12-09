package iuh.fit.se.dtos.dashboard;

public class DashboardStatsDTO {
    private Double totalRevenue;
    private Long totalOrders;
    private Long totalProducts;
    private Long totalCustomers;

    public DashboardStatsDTO(Double totalRevenue, Long totalOrders, Long totalProducts, Long totalCustomers) {
        this.totalRevenue = totalRevenue;
        this.totalOrders = totalOrders;
        this.totalProducts = totalProducts;
        this.totalCustomers = totalCustomers;
    }

    public Double getTotalRevenue() {
        return totalRevenue;
    }

    public void setTotalRevenue(Double totalRevenue) {
        this.totalRevenue = totalRevenue;
    }

    public Long getTotalOrders() {
        return totalOrders;
    }

    public void setTotalOrders(Long totalOrders) {
        this.totalOrders = totalOrders;
    }

    public Long getTotalProducts() {
        return totalProducts;
    }

    public void setTotalProducts(Long totalProducts) {
        this.totalProducts = totalProducts;
    }

    public Long getTotalCustomers() {
        return totalCustomers;
    }

    public void setTotalCustomers(Long totalCustomers) {
        this.totalCustomers = totalCustomers;
    }
}
