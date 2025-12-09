package iuh.fit.se.services.impl;

import iuh.fit.se.dtos.coupon.CouponRequestDTO;
import iuh.fit.se.dtos.coupon.CouponResponseDTO;
import iuh.fit.se.entities.coupon.Coupon;
import iuh.fit.se.entities.coupon.CouponStatus;
import iuh.fit.se.mappers.CouponMapper;
import iuh.fit.se.repositories.CouponRepository;
import iuh.fit.se.services.CouponService;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
public class CouponServiceImpl implements CouponService {

    private final CouponRepository couponRepository;
    private final CouponMapper couponMapper;

    public CouponServiceImpl(CouponRepository couponRepository, CouponMapper couponMapper) {
        this.couponRepository = couponRepository;
        this.couponMapper = couponMapper;
    }

    @Override
    public CouponResponseDTO createCoupon(CouponRequestDTO dto) {
        if (couponRepository.findByCode(dto.getCode()).isPresent()) {
            throw new RuntimeException("Coupon code already exists!");
        }
        Coupon coupon = couponMapper.toEntity(dto);

        coupon.setStatus(CouponStatus.ACTIVE);

        return couponMapper.toResponseDTO(couponRepository.save(coupon));
    }

    @Override
    public CouponResponseDTO updateCoupon(Long id, CouponRequestDTO dto) {
        Coupon existing = couponRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Coupon not found with id: " + id));

        existing.setCode(dto.getCode());
        existing.setDiscountAmount(dto.getDiscountAmount());
        existing.setMinOrderValue(dto.getMinOrderValue());
        existing.setStartDate(dto.getStartDate());
        existing.setEndDate(dto.getEndDate());

        return couponMapper.toResponseDTO(couponRepository.save(existing));
    }

    //DELETE (SOFT DELETE)
    @Override
    public void deleteCoupon(Long id) {
        Coupon coupon = couponRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Coupon not found with id: " + id));

        //set status = DELETED
        coupon.setStatus(CouponStatus.DELETED);
        couponRepository.save(coupon);
    }

    @Override
    public CouponResponseDTO getCouponById(Long id) {
        return couponRepository.findById(id)
                .map(couponMapper::toResponseDTO)
                .orElseThrow(() -> new EntityNotFoundException("Coupon not found with id: " + id));
    }

    @Override
    public List<CouponResponseDTO> getAllCoupons() {
        return couponRepository.findByStatusNot(CouponStatus.DELETED)
                .stream()
                .map(couponMapper::toResponseDTO)
                .collect(Collectors.toList());
    }

    @Override
    public CouponResponseDTO getCouponByCode(String code) {
        return couponRepository.findByCode(code)
                .map(couponMapper::toResponseDTO)
                .orElseThrow(() -> new EntityNotFoundException("Coupon not found with code: " + code));
    }

    //UPDATE STATUS
    @Override
    public CouponResponseDTO updateCouponStatus(Long id, String statusStr) {
        Coupon coupon = couponRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Coupon not found with id: " + id));

        try {
            CouponStatus newStatus = CouponStatus.valueOf(statusStr.toUpperCase());
            coupon.setStatus(newStatus);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid status: " + statusStr);
        }

        return couponMapper.toResponseDTO(couponRepository.save(coupon));
    }
}
