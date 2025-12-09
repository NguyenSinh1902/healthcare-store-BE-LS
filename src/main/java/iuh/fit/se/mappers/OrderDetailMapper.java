package iuh.fit.se.mappers;

import iuh.fit.se.dtos.order.OrderDetailRequestDTO;
import iuh.fit.se.dtos.order.OrderDetailResponseDTO;
import iuh.fit.se.entities.order.OrderDetail;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface OrderDetailMapper {

    //RequestDTO - Entity
    @Mapping(target = "idOrderDetail", ignore = true)
    @Mapping(target = "order", ignore = true)
    @Mapping(target = "product.idProduct", source = "idProduct")
    OrderDetail toEntity(OrderDetailRequestDTO dto);

    //Entity - ResponseDTO
    @Mapping(target = "idProduct", source = "product.idProduct")
    @Mapping(target = "productName", source = "product.nameProduct")
    @Mapping(target = "imageProduct", source = "product.imageProduct")
    OrderDetailResponseDTO toResponseDTO(OrderDetail entity);
}
