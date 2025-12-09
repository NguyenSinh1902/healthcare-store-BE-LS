package iuh.fit.se.repositories;

import iuh.fit.se.entities.cartitem.CartItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CartItemRepository extends JpaRepository<CartItem, Long> {

    //find By Cart_IdCart
    List<CartItem> findByCart_IdCart(Long cartId);

    //find By Cart IdCart And Product IdProduct
    Optional<CartItem> findByCart_IdCartAndProduct_IdProduct(Long cartId, Long productId);

    void deleteAllByCart_IdCart(Long cartId);

}
