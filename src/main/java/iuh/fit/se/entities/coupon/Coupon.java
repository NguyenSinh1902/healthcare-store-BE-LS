package iuh.fit.se.entities.coupon;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import java.time.LocalDate;

@Entity
@Table(name = "coupons")
public class Coupon {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_coupon")
    private Long idCoupon;

    @NotBlank(message = "Coupon code is required")
    @Size(max = 50, message = "Code must be less than 50 characters")
    @Column(unique = true, nullable = false)
    private String code;

    @NotNull(message = "Discount amount is required")
    @PositiveOrZero(message = "Discount amount must be >= 0")
    private Double discountAmount;

    @NotNull(message = "Minimum order value is required")
    @PositiveOrZero(message = "Minimum order value must be >= 0")
    private Double minOrderValue;

    private LocalDate startDate;
    private LocalDate endDate;

    //    private boolean active = true;
    // 👇 THAY ACTIVE BẰNG CÁI NÀY
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CouponStatus status = CouponStatus.ACTIVE; // Mặc định là ACTIVE

    // Constructors
    public Coupon() {}

    public Coupon(Long idCoupon, String code, Double discountAmount, Double minOrderValue, LocalDate startDate, LocalDate endDate, CouponStatus status) {
        this.idCoupon = idCoupon;
        this.code = code;
        this.discountAmount = discountAmount;
        this.minOrderValue = minOrderValue;
        this.startDate = startDate;
        this.endDate = endDate;
        this.status = status;
    }

    // Getters and setters

    public Long getIdCoupon() {
        return idCoupon;
    }

    public void setIdCoupon(Long idCoupon) {
        this.idCoupon = idCoupon;
    }

    public @NotBlank(message = "Coupon code is required") @Size(max = 50, message = "Code must be less than 50 characters") String getCode() {
        return code;
    }

    public void setCode(@NotBlank(message = "Coupon code is required") @Size(max = 50, message = "Code must be less than 50 characters") String code) {
        this.code = code;
    }

    public @NotNull(message = "Discount amount is required") @PositiveOrZero(message = "Discount amount must be >= 0") Double getDiscountAmount() {
        return discountAmount;
    }

    public void setDiscountAmount(@NotNull(message = "Discount amount is required") @PositiveOrZero(message = "Discount amount must be >= 0") Double discountAmount) {
        this.discountAmount = discountAmount;
    }

    public @NotNull(message = "Minimum order value is required") @PositiveOrZero(message = "Minimum order value must be >= 0") Double getMinOrderValue() {
        return minOrderValue;
    }

    public void setMinOrderValue(@NotNull(message = "Minimum order value is required") @PositiveOrZero(message = "Minimum order value must be >= 0") Double minOrderValue) {
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
