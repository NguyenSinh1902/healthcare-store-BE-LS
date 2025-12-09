package iuh.fit.se.repositories;

import iuh.fit.se.entities.coupon.Coupon;
import iuh.fit.se.entities.coupon.CouponStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CouponRepository extends JpaRepository<Coupon, Long> {
    Optional<Coupon> findByCode(String code);

    //Tìm tất cả coupon ngoại trừ trạng thái DELETED
    List<Coupon> findByStatusNot(CouponStatus status);
}
