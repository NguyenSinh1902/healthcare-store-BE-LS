package iuh.fit.se.entities.cart;

import iuh.fit.se.entities.auth.User;
import iuh.fit.se.entities.cartitem.CartItem;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "carts")
public class Cart {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_cart")
    private Long idCart;

    @NotNull
    @Column(name = "total_amount")
    private Double totalAmount = 0.0;

    //1 Cart - 1 User
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "id_user", nullable = false)
    private User user;

    //1 Cart - N CartItems
    @OneToMany(mappedBy = "cart", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private Set<CartItem> cartItems = new HashSet<>();

    public Cart() {
    }

    public Cart(Long idCart, Double totalAmount, User user, Set<CartItem> cartItems) {
        this.idCart = idCart;
        this.totalAmount = totalAmount;
        this.user = user;
        this.cartItems = cartItems;
    }

    // Getters & setters
    public Long getIdCart() {
        return idCart;
    }

    public void setIdCart(Long idCart) {
        this.idCart = idCart;
    }

    public Double getTotalAmount() {
        return totalAmount;
    }

    public void setTotalAmount(Double totalAmount) {
        this.totalAmount = totalAmount;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Set<CartItem> getCartItems() {
        return cartItems;
    }

    public void setCartItems(Set<CartItem> cartItems) {
        this.cartItems = cartItems;
    }
}
