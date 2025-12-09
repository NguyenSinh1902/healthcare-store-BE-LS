package iuh.fit.se.mappers;

import iuh.fit.se.dtos.coupon.CouponRequestDTO;
import iuh.fit.se.dtos.coupon.CouponResponseDTO;
import iuh.fit.se.entities.coupon.Coupon;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface CouponMapper {

    //RequestDTO → Entity
    @Mapping(target = "idCoupon", ignore = true)
    Coupon toEntity(CouponRequestDTO dto);

    //Entity → ResponseDTO
    CouponResponseDTO toResponseDTO(Coupon entity);
}
