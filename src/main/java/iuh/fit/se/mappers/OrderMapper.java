package iuh.fit.se.mappers;

import iuh.fit.se.dtos.order.OrderRequestDTO;
import iuh.fit.se.dtos.order.OrderResponseDTO;
import iuh.fit.se.entities.order.Order;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring", uses = {OrderDetailMapper.class})
public interface OrderMapper {

    //RequestDTO - Entity
    @Mapping(target = "idOrder", ignore = true)
    @Mapping(target = "user", ignore = true)
    @Mapping(target = "coupon.idCoupon", source = "idCoupon")
    @Mapping(target = "orderDetails", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "orderDate", expression = "java(java.time.LocalDateTime.now())")
    Order toEntity(OrderRequestDTO dto);

    //Entity - ResponseDTO
    @Mapping(target = "couponCode", source = "coupon.code")
    @Mapping(target = "orderDetails", source = "orderDetails")
    @Mapping(target = "idUser", source = "user.idUser")
    OrderResponseDTO toResponseDTO(Order entity);

}
