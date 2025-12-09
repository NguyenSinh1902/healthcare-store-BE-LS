package iuh.fit.se.controllers;

import iuh.fit.se.dtos.coupon.CouponRequestDTO;
import iuh.fit.se.dtos.coupon.CouponResponseDTO;
import iuh.fit.se.services.CouponService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/coupons")
@CrossOrigin(origins = "*")
public class CouponController {

    private final CouponService couponService;

    public CouponController(CouponService couponService) {
        this.couponService = couponService;
    }

    //CREATE
    @PostMapping
    public ResponseEntity<CouponResponseDTO> createCoupon(@Valid @RequestBody CouponRequestDTO dto) {
        return ResponseEntity.ok(couponService.createCoupon(dto));
    }

    //UPDATE
    @PutMapping("/{id}")
    public ResponseEntity<CouponResponseDTO> updateCoupon(@PathVariable Long id, @Valid @RequestBody CouponRequestDTO dto) {
        return ResponseEntity.ok(couponService.updateCoupon(id, dto));
    }

    //DELETE
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteCoupon(@PathVariable Long id) {
        couponService.deleteCoupon(id);
        return ResponseEntity.noContent().build();
    }

    //GET BY ID
    @GetMapping("/{id}")
    public ResponseEntity<CouponResponseDTO> getCouponById(@PathVariable Long id) {
        return ResponseEntity.ok(couponService.getCouponById(id));
    }

    //GET ALL
    @GetMapping
    public ResponseEntity<List<CouponResponseDTO>> getAllCoupons() {
        return ResponseEntity.ok(couponService.getAllCoupons());
    }

    //GET BY CODE
    @GetMapping("/code/{code}")
    public ResponseEntity<CouponResponseDTO> getCouponByCode(@PathVariable String code) {
        return ResponseEntity.ok(couponService.getCouponByCode(code));
    }

    //API Update trạng thái
    @PutMapping("/{id}/status")
    public ResponseEntity<CouponResponseDTO> updateStatus(
            @PathVariable Long id,
            @RequestParam String status
    ) {
        return ResponseEntity.ok(couponService.updateCouponStatus(id, status));
    }
}
