package iuh.fit.se.dtos.order;

import java.time.LocalDateTime;
import java.util.List;

public class OrderResponseDTO {

    private Long idOrder;
    private Long idUser;
    private LocalDateTime orderDate;
    private String deliveryAddress;
    private String paymentMethod;
    private Double totalAmount;
    private Double couponDiscount;
    private Double finalAmount;
    private String status;
    private String couponCode;
    private List<OrderDetailResponseDTO> orderDetails;

    public OrderResponseDTO() {}

    public OrderResponseDTO(Long idOrder, LocalDateTime orderDate, String deliveryAddress, String paymentMethod, Double totalAmount, Double couponDiscount, Double finalAmount, String status, String couponCode, List<OrderDetailResponseDTO> orderDetails) {
        this.idOrder = idOrder;
        this.orderDate = orderDate;
        this.deliveryAddress = deliveryAddress;
        this.paymentMethod = paymentMethod;
        this.totalAmount = totalAmount;
        this.couponDiscount = couponDiscount;
        this.finalAmount = finalAmount;
        this.status = status;
        this.couponCode = couponCode;
        this.orderDetails = orderDetails;
    }

    // Getters và Setters

    public Long getIdOrder() {
        return idOrder;
    }

    public void setIdOrder(Long idOrder) {
        this.idOrder = idOrder;
    }

    public Long getIdUser() {
        return idUser;
    }

    public void setIdUser(Long idUser) {
        this.idUser = idUser;
    }

    public LocalDateTime getOrderDate() {
        return orderDate;
    }

    public void setOrderDate(LocalDateTime orderDate) {
        this.orderDate = orderDate;
    }

    public String getDeliveryAddress() {
        return deliveryAddress;
    }

    public void setDeliveryAddress(String deliveryAddress) {
        this.deliveryAddress = deliveryAddress;
    }

    public String getPaymentMethod() {
        return paymentMethod;
    }

    public void setPaymentMethod(String paymentMethod) {
        this.paymentMethod = paymentMethod;
    }

    public Double getTotalAmount() {
        return totalAmount;
    }

    public void setTotalAmount(Double totalAmount) {
        this.totalAmount = totalAmount;
    }

    public Double getCouponDiscount() {
        return couponDiscount;
    }

    public void setCouponDiscount(Double couponDiscount) {
        this.couponDiscount = couponDiscount;
    }

    public Double getFinalAmount() {
        return finalAmount;
    }

    public void setFinalAmount(Double finalAmount) {
        this.finalAmount = finalAmount;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getCouponCode() {
        return couponCode;
    }

    public void setCouponCode(String couponCode) {
        this.couponCode = couponCode;
    }

    public List<OrderDetailResponseDTO> getOrderDetails() {
        return orderDetails;
    }

    public void setOrderDetails(List<OrderDetailResponseDTO> orderDetails) {
        this.orderDetails = orderDetails;
    }
}
