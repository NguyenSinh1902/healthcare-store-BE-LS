package iuh.fit.se.dtos.coupon;

import iuh.fit.se.entities.coupon.CouponStatus;

import java.time.LocalDate;

public class CouponResponseDTO {
    private Long idCoupon;
    private String code;
    private Double discountAmount;
    private Double minOrderValue;
    private LocalDate startDate;
    private LocalDate endDate;
    // private boolean active;
    private CouponStatus status;

    public CouponResponseDTO() {}

    public CouponResponseDTO(Long idCoupon, String code, Double discountAmount, Double minOrderValue, LocalDate startDate, LocalDate endDate, CouponStatus status) {
        this.idCoupon = idCoupon;
        this.code = code;
        this.discountAmount = discountAmount;
        this.minOrderValue = minOrderValue;
        this.startDate = startDate;
        this.endDate = endDate;
        this.status = status;
    }

    // Getters và Setters

    public Long getIdCoupon() {
        return idCoupon;
    }

    public void setIdCoupon(Long idCoupon) {
        this.idCoupon = idCoupon;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public Double getDiscountAmount() {
        return discountAmount;
    }

    public void setDiscountAmount(Double discountAmount) {
        this.discountAmount = discountAmount;
    }

    public Double getMinOrderValue() {
        return minOrderValue;
    }

    public void setMinOrderValue(Double minOrderValue) {
        this.minOrderValue = minOrderValue;
    }

    public LocalDate getStartDate() {
        return startDate;
    }

    public void setStartDate(LocalDate startDate) {
        this.startDate = startDate;
    }

    public LocalDate getEndDate() {
        return endDate;
    }

    public void setEndDate(LocalDate endDate) {
        this.endDate = endDate;
    }

    public CouponStatus getStatus() {
        return status;
    }

    public void setStatus(CouponStatus status) {
        this.status = status;
    }
}
