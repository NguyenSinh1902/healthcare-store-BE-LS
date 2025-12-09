package iuh.fit.se.dtos.order;

import com.fasterxml.jackson.annotation.JsonIgnore;
import iuh.fit.se.entities.order.PaymentMethod;
import jakarta.validation.constraints.*;

import java.util.List;

public class OrderRequestDTO {

    @NotBlank(message = "Delivery address is required")
    private String deliveryAddress;

    @NotNull(message = "Payment method is required") // CASH, CARD
    private PaymentMethod paymentMethod;

    private Long idCoupon;

    private List<Long> selectedCartItemIds;

    // Các field dưới BE sẽ tự tính, không để FE gửi lên
    @JsonIgnore
    private Double totalAmount;

    @JsonIgnore
    private Double couponDiscount;

    @JsonIgnore
    private Double finalAmount;

    // --- Constructors ---
    public OrderRequestDTO() {}

    public OrderRequestDTO(String deliveryAddress, PaymentMethod paymentMethod, Long idCoupon, List<Long> selectedCartItemIds) {
        this.deliveryAddress = deliveryAddress;
        this.paymentMethod = paymentMethod;
        this.idCoupon = idCoupon;
        this.selectedCartItemIds = selectedCartItemIds;
    }

    // --- Getters & Setters ---
    public @NotBlank(message = "Delivery address is required") String getDeliveryAddress() {
        return deliveryAddress;
    }

    public void setDeliveryAddress(@NotBlank(message = "Delivery address is required") String deliveryAddress) {
        this.deliveryAddress = deliveryAddress;
    }

    public @NotNull(message = "Payment method is required") PaymentMethod getPaymentMethod() {
        return paymentMethod;
    }

    public void setPaymentMethod(@NotNull(message = "Payment method is required") PaymentMethod paymentMethod) {
        this.paymentMethod = paymentMethod;
    }

    public Long getIdCoupon() {
        return idCoupon;
    }

    public void setIdCoupon(Long idCoupon) {
        this.idCoupon = idCoupon;
    }

    public List<Long> getSelectedCartItemIds() {
        return selectedCartItemIds;
    }

    public void setSelectedCartItemIds(List<Long> selectedCartItemIds) {
        this.selectedCartItemIds = selectedCartItemIds;
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
}
