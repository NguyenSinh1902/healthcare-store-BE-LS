package iuh.fit.se.entities.order;

import iuh.fit.se.entities.auth.User;
import iuh.fit.se.entities.coupon.Coupon;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "orders")
public class Order {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_order")
    private Long idOrder;

    private LocalDateTime orderDate = LocalDateTime.now();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "id_user", nullable = false)
    private User user;

    @NotBlank(message = "Delivery address is required")
    @Size(max = 255)
    private String deliveryAddress;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PaymentMethod paymentMethod = PaymentMethod.CASH;

    @NotNull
    @PositiveOrZero
    private Double totalAmount;

    @PositiveOrZero
    private Double couponDiscount = 0.0;

    @NotNull
    @PositiveOrZero
    private Double finalAmount;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OrderStatus status = OrderStatus.PENDING;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "id_coupon")
    private Coupon coupon;

    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<OrderDetail> orderDetails = new HashSet<>();

    public Order() {}

    public Order(Long idOrder, LocalDateTime orderDate, User user, String deliveryAddress, PaymentMethod paymentMethod, Double totalAmount, Double couponDiscount, Double finalAmount, OrderStatus status, Coupon coupon, Set<OrderDetail> orderDetails) {
        this.idOrder = idOrder;
        this.orderDate = orderDate;
        this.user = user;
        this.deliveryAddress = deliveryAddress;
        this.paymentMethod = paymentMethod;
        this.totalAmount = totalAmount;
        this.couponDiscount = couponDiscount;
        this.finalAmount = finalAmount;
        this.status = status;
        this.coupon = coupon;
        this.orderDetails = orderDetails;
    }

    // getters and setters

    public Long getIdOrder() {
        return idOrder;
    }

    public void setIdOrder(Long idOrder) {
        this.idOrder = idOrder;
    }

    public LocalDateTime getOrderDate() {
        return orderDate;
    }

    public void setOrderDate(LocalDateTime orderDate) {
        this.orderDate = orderDate;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public @NotBlank(message = "Delivery address is required") @Size(max = 255) String getDeliveryAddress() {
        return deliveryAddress;
    }

    public void setDeliveryAddress(@NotBlank(message = "Delivery address is required") @Size(max = 255) String deliveryAddress) {
        this.deliveryAddress = deliveryAddress;
    }

    public PaymentMethod getPaymentMethod() {
        return paymentMethod;
    }

    public void setPaymentMethod(PaymentMethod paymentMethod) {
        this.paymentMethod = paymentMethod;
    }

    public @NotNull @PositiveOrZero Double getTotalAmount() {
        return totalAmount;
    }

    public void setTotalAmount(@NotNull @PositiveOrZero Double totalAmount) {
        this.totalAmount = totalAmount;
    }

    public @PositiveOrZero Double getCouponDiscount() {
        return couponDiscount;
    }

    public void setCouponDiscount(@PositiveOrZero Double couponDiscount) {
        this.couponDiscount = couponDiscount;
    }

    public @NotNull @PositiveOrZero Double getFinalAmount() {
        return finalAmount;
    }

    public void setFinalAmount(@NotNull @PositiveOrZero Double finalAmount) {
        this.finalAmount = finalAmount;
    }

    public OrderStatus getStatus() {
        return status;
    }

    public void setStatus(OrderStatus status) {
        this.status = status;
    }

    public Coupon getCoupon() {
        return coupon;
    }

    public void setCoupon(Coupon coupon) {
        this.coupon = coupon;
    }

    public Set<OrderDetail> getOrderDetails() {
        return orderDetails;
    }

    public void setOrderDetails(Set<OrderDetail> orderDetails) {
        this.orderDetails = orderDetails;
    }
}
