package iuh.fit.se.mappers;

import iuh.fit.se.dtos.cartitem.CartItemRequestDTO;
import iuh.fit.se.dtos.cartitem.CartItemResponseDTO;
import iuh.fit.se.entities.cartitem.CartItem;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface CartItemMapper {

    //Entity - ResponseDTO
    @Mapping(target = "idProduct", source = "product.idProduct")
    @Mapping(target = "nameProduct", source = "product.nameProduct")
    @Mapping(target = "imageProduct", source = "product.imageProduct")
    @Mapping(target = "unitPrice", source = "product.price")
    @Mapping(target = "active", source = "product.active")
    CartItemResponseDTO toResponseDTO(CartItem entity);

    //RequestDTO - Entity
    @Mapping(target = "idCartItem", ignore = true)
    @Mapping(target = "cart", ignore = true)
    @Mapping(target = "product", ignore = true)
    @Mapping(target = "totalPrice", ignore = true) // se tinh trong service = product.price * quantity
    CartItem toEntity(CartItemRequestDTO dto);
}
