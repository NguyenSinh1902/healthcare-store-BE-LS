package iuh.fit.se.mappers;

import iuh.fit.se.dtos.product.ProductRequestDTO;
import iuh.fit.se.dtos.product.ProductResponseDTO;
import iuh.fit.se.dtos.product.ProductDetailDTO;
import iuh.fit.se.entities.product.Product;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface ProductMapper {

    // Entity to ProductResponseDTO (for product listing or response)
    @Mapping(target = "idCategory", source = "category.idCategory")
    @Mapping(target = "categoryName", source = "category.nameCategory")
    @Mapping(target = "thumbnails", source = "thumbnails")  // optional
    ProductResponseDTO toResponseDTO(Product product);

    // Entity to ProductDetailDTO (for product detail page)
    @Mapping(target = "categoryName", source = "category.nameCategory")
    @Mapping(target = "idCategory", source = "category.idCategory")
    @Mapping(target = "thumbnails", source = "thumbnails")
    ProductDetailDTO toDetailDTO(Product product);

    // ProductRequestDTO to Product entity (for create or update)
    @Mapping(target = "category.idCategory", source = "idCategory")
    Product toEntity(ProductRequestDTO productRequestDTO);
}
