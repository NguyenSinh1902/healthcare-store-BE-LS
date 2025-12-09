//package iuh.fit.se.services.impl;
//
//import iuh.fit.se.dtos.cartitem.CartItemRequestDTO;
//import iuh.fit.se.dtos.cartitem.CartItemResponseDTO;
//import iuh.fit.se.entities.cart.Cart;
//import iuh.fit.se.entities.cartitem.CartItem;
//import iuh.fit.se.entities.product.Product;
//import iuh.fit.se.exceptions.NotFoundException;
//import iuh.fit.se.mappers.CartItemMapper;
//import iuh.fit.se.repositories.CartItemRepository;
//import iuh.fit.se.repositories.CartRepository;
//import iuh.fit.se.repositories.ProductRepository;
//import iuh.fit.se.services.CartItemService;
//import jakarta.transaction.Transactional;
//import org.springframework.stereotype.Service;
//
//import java.util.List;
//import java.util.stream.Collectors;
//
//@Service
//public class CartItemServiceImpl implements CartItemService {
//
//    private final CartItemRepository cartItemRepository;
//    private final CartRepository cartRepository;
//    private final ProductRepository productRepository;
//    private final CartItemMapper cartItemMapper;
//
//    public CartItemServiceImpl(CartItemRepository cartItemRepository,
//                               CartRepository cartRepository,
//                               ProductRepository productRepository,
//                               CartItemMapper cartItemMapper) {
//        this.cartItemRepository = cartItemRepository;
//        this.cartRepository = cartRepository;
//        this.productRepository = productRepository;
//        this.cartItemMapper = cartItemMapper;
//    }
//
//    //Get all items by cart ID
//    @Override
//    public List<CartItemResponseDTO> getItemsByCartId(Long cartId) {
//        List<CartItem> items = cartItemRepository.findByCart_IdCart(cartId);
//        if (items.isEmpty()) {
//            throw new NotFoundException("No cart items found for cart ID: " + cartId);
//        }
//        return items.stream()
//                .map(cartItemMapper::toResponseDTO)
//                .collect(Collectors.toList());
//    }
//
//    //Get a item
//    @Override
//    public CartItemResponseDTO getItemById(Long id) {
//        CartItem item = cartItemRepository.findById(id)
//                .orElseThrow(() -> new NotFoundException("Cart item not found with ID: " + id));
//        return cartItemMapper.toResponseDTO(item);
//    }
//
//    //Add cartitem
//    @Transactional
//    @Override
//    public CartItemResponseDTO addCartItem(CartItemRequestDTO dto) {
//        Cart cart = cartRepository.findById(dto.getIdCart())
//                .orElseThrow(() -> new NotFoundException("Cart not found with ID: " + dto.getIdCart()));
//
//        Product product = productRepository.findById(dto.getIdProduct())
//                .orElseThrow(() -> new NotFoundException("Product not found with ID: " + dto.getIdProduct()));
//
//        //Check for duplicate products in cart
//        CartItem existing = cartItemRepository.findByCart_IdCartAndProduct_IdProduct(cart.getIdCart(), product.getIdProduct())
//                .orElse(null);
//
//        if (existing != null) {
//            existing.setQuantity(existing.getQuantity() + dto.getQuantity());
//            existing.setTotalPrice(existing.getQuantity() * product.getPrice());
//            return cartItemMapper.toResponseDTO(cartItemRepository.save(existing));
//        }
//
//        CartItem newItem = cartItemMapper.toEntity(dto);
//        newItem.setCart(cart);
//        newItem.setProduct(product);
//        newItem.setTotalPrice(product.getPrice() * dto.getQuantity());
//
//        cartItemRepository.save(newItem);
//        return cartItemMapper.toResponseDTO(newItem);
//    }
//
//    //Update quantity
//    @Transactional
//    @Override
//    public CartItemResponseDTO updateCartItem(Long id, Integer newQuantity) {
//        CartItem item = cartItemRepository.findById(id)
//                .orElseThrow(() -> new NotFoundException("Cart item not found with ID: " + id));
//
//        if (newQuantity <= 0) {
//            cartItemRepository.delete(item);
//            throw new NotFoundException("Item removed because quantity <= 0");
//        }
//
//        item.setQuantity(newQuantity);
//        item.setTotalPrice(item.getProduct().getPrice() * newQuantity);
//        cartItemRepository.save(item);
//        return cartItemMapper.toResponseDTO(item);
//    }
//
//    //Delete cartitem
//    @Transactional
//    @Override
//    public void deleteCartItem(Long id) {
//        CartItem item = cartItemRepository.findById(id)
//                .orElseThrow(() -> new NotFoundException("Cart item not found with ID: " + id));
//        cartItemRepository.delete(item);
//    }
//}
