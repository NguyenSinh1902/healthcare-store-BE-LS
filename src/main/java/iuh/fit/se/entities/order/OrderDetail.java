package iuh.fit.se.entities.order;

import iuh.fit.se.entities.product.Product;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;

@Entity
@Table(name = "order_details")
public class OrderDetail {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_order_detail")
    private Long idOrderDetail;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "id_order", nullable = false)
    private Order order;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "id_product", nullable = false)
    private Product product;

    @NotNull
    @Positive(message = "Quantity must be greater than 0")
    private Integer quantity;

    @NotNull
    @Positive(message = "Unit price must be greater than 0")
    private Double unitPrice;

    @NotNull
    @PositiveOrZero
    private Double totalPrice;

    // Constructors
    public OrderDetail() {}

    public OrderDetail(Long idOrderDetail, Order order, Product product, Integer quantity, Double unitPrice, Double totalPrice) {
        this.idOrderDetail = idOrderDetail;
        this.order = order;
        this.product = product;
        this.quantity = quantity;
        this.unitPrice = unitPrice;
        this.totalPrice = totalPrice;
    }

    // Getters and setters

    public Long getIdOrderDetail() {
        return idOrderDetail;
    }

    public void setIdOrderDetail(Long idOrderDetail) {
        this.idOrderDetail = idOrderDetail;
    }

    public Order getOrder() {
        return order;
    }

    public void setOrder(Order order) {
        this.order = order;
    }

    public Product getProduct() {
        return product;
    }

    public void setProduct(Product product) {
        this.product = product;
    }

    public @NotNull @Positive(message = "Quantity must be greater than 0") Integer getQuantity() {
        return quantity;
    }

    public void setQuantity(@NotNull @Positive(message = "Quantity must be greater than 0") Integer quantity) {
        this.quantity = quantity;
    }

    public @NotNull @Positive(message = "Unit price must be greater than 0") Double getUnitPrice() {
        return unitPrice;
    }

    public void setUnitPrice(@NotNull @Positive(message = "Unit price must be greater than 0") Double unitPrice) {
        this.unitPrice = unitPrice;
    }

    public @NotNull @PositiveOrZero Double getTotalPrice() {
        return totalPrice;
    }

    public void setTotalPrice(@NotNull @PositiveOrZero Double totalPrice) {
        this.totalPrice = totalPrice;
    }
}
