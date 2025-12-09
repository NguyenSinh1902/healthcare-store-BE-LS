package iuh.fit.se.repositories;

import iuh.fit.se.entities.cart.Cart;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CartRepository extends JpaRepository<Cart, Long> {

    //find By User_Id
    Optional<Cart> findByUser_IdUser(Long userId);
}
