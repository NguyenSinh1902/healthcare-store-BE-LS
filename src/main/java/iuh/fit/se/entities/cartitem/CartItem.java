package iuh.fit.se.entities.cartitem;

import iuh.fit.se.entities.cart.Cart;
import iuh.fit.se.entities.product.Product;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

@Entity
@Table(name = "cart_items")
public class CartItem {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_cart_item")
    private Long idCartItem;

    @NotNull
    @Positive
    private Integer quantity;

    @NotNull
    private Double totalPrice;

    //N CartItem - 1 Cart
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "id_cart", nullable = false)
    private Cart cart;

    //N CartItem - 1 Product
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "id_product", nullable = false)
    private Product product;

    public CartItem() {
    }

    public CartItem(Long idCartItem, Integer quantity, Double totalPrice, Cart cart, Product product) {
        this.idCartItem = idCartItem;
        this.quantity = quantity;
        this.totalPrice = totalPrice;
        this.cart = cart;
        this.product = product;
    }

    // Getters & setters
    public Long getIdCartItem() {
        return idCartItem;
    }

    public void setIdCartItem(Long idCartItem) {
        this.idCartItem = idCartItem;
    }

    public Integer getQuantity() {
        return quantity;
    }

    public void setQuantity(Integer quantity) {
        this.quantity = quantity;
    }

    public Double getTotalPrice() {
        return totalPrice;
    }

    public void setTotalPrice(Double totalPrice) {
        this.totalPrice = totalPrice;
    }

    public Cart getCart() {
        return cart;
    }

    public void setCart(Cart cart) {
        this.cart = cart;
    }

    public Product getProduct() {
        return product;
    }

    public void setProduct(Product product) {
        this.product = product;
    }
}
