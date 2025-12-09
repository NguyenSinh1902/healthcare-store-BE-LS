package iuh.fit.se.services;

import iuh.fit.se.dtos.coupon.CouponRequestDTO;
import iuh.fit.se.dtos.coupon.CouponResponseDTO;

import java.util.List;

public interface CouponService {

    CouponResponseDTO createCoupon(CouponRequestDTO dto);

    CouponResponseDTO updateCoupon(Long id, CouponRequestDTO dto);

    void deleteCoupon(Long id);

    CouponResponseDTO getCouponById(Long id);

    List<CouponResponseDTO> getAllCoupons();

    CouponResponseDTO getCouponByCode(String code);

    CouponResponseDTO updateCouponStatus(Long id, String statusStr);
}
