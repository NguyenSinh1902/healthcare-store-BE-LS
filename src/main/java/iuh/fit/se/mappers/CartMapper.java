package iuh.fit.se.mappers;

import iuh.fit.se.dtos.cart.CartRequestDTO;
import iuh.fit.se.dtos.cart.CartResponseDTO;
import iuh.fit.se.entities.cart.Cart;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring", uses = {CartItemMapper.class})
public interface CartMapper {

    //Entity - ResponseDTO
    @Mapping(target = "idUser", source = "user.idUser")
    @Mapping(target = "items", source = "cartItems")
    CartResponseDTO toResponseDTO(Cart entity);

    //RequestDTO - Entity
    @Mapping(target = "idCart", ignore = true)
    @Mapping(target = "user", ignore = true)
    @Mapping(target = "cartItems", ignore = true)
    Cart toEntity(CartRequestDTO dto);
}
