package iuh.fit.se.services.impl;

import iuh.fit.se.dtos.order.OrderRequestDTO;
import iuh.fit.se.dtos.order.OrderResponseDTO;
import iuh.fit.se.entities.cart.Cart;
import iuh.fit.se.entities.cartitem.CartItem;
import iuh.fit.se.entities.coupon.Coupon;
import iuh.fit.se.entities.coupon.CouponStatus;
import iuh.fit.se.entities.order.Order;
import iuh.fit.se.entities.order.OrderDetail;
import iuh.fit.se.entities.order.OrderStatus;
import iuh.fit.se.mappers.*;
import iuh.fit.se.repositories.*;
import iuh.fit.se.services.CartService;
import iuh.fit.se.services.OrderService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
public class OrderServiceImpl implements OrderService {

    private final OrderRepository orderRepository;
    private final OrderDetailRepository orderDetailRepository;
    private final CartRepository cartRepository;
    private final CartItemRepository cartItemRepository;
    private final UserRepository userRepository;
    private final CouponRepository couponRepository;

    private final OrderMapper orderMapper;
    private final OrderDetailMapper orderDetailMapper;
    private final CartService cartService;

    public OrderServiceImpl(OrderRepository orderRepository, OrderDetailRepository orderDetailRepository, CartRepository cartRepository, CartItemRepository cartItemRepository, UserRepository userRepository, CouponRepository couponRepository, OrderMapper orderMapper, OrderDetailMapper orderDetailMapper, CartService cartService) {
        this.orderRepository = orderRepository;
        this.orderDetailRepository = orderDetailRepository;
        this.cartRepository = cartRepository;
        this.cartItemRepository = cartItemRepository;
        this.userRepository = userRepository;
        this.couponRepository = couponRepository;
        this.orderMapper = orderMapper;
        this.orderDetailMapper = orderDetailMapper;
        this.cartService = cartService;
    }

    @Override
    public OrderResponseDTO createOrderFromCart(Long userId, OrderRequestDTO orderRequestDTO) {
        //Get user cart
        Cart cart = cartRepository.findByUser_IdUser(userId)
                .orElseThrow(() -> new RuntimeException("Cart not found for user id: " + userId));

        //Get the CartItem list
        List<CartItem> cartItems;

        List<Long> selectedIds = orderRequestDTO.getSelectedCartItemIds();

        if (selectedIds != null && !selectedIds.isEmpty()) {

            cartItems = cartItemRepository.findAllById(selectedIds);

            boolean allBelongToUser = cartItems.stream()
                    .allMatch(item -> item.getCart().getIdCart().equals(cart.getIdCart()));

            if (!allBelongToUser) {
                throw new RuntimeException("Phát hiện lỗi bảo mật: Sản phẩm được chọn không thuộc giỏ hàng của bạn.");
            }
        } else {
            throw new RuntimeException("Vui lòng chọn ít nhất một sản phẩm để thanh toán.");
        }

        if (cartItems.isEmpty()) {
            throw new RuntimeException("Không tìm thấy sản phẩm nào để thanh toán.");
        }

        //Calculate total amount
        double totalAmount = cartItems.stream()
                .mapToDouble(item -> item.getProduct().getPrice() * item.getQuantity())
                .sum();

        //Validate & Apply Coupon
        double couponDiscount = 0.0;
        Coupon coupon = null;

        if (orderRequestDTO.getIdCoupon() != null) {
            coupon = couponRepository.findById(orderRequestDTO.getIdCoupon())
                    .orElseThrow(() -> new RuntimeException("Coupon not found"));

            if (coupon.getStatus() != CouponStatus.ACTIVE) {
                throw new RuntimeException("Coupon is currently inactive.");
            }

            LocalDate now = LocalDate.now();
            if ((coupon.getStartDate() != null && now.isBefore(coupon.getStartDate())) ||
                    (coupon.getEndDate() != null && now.isAfter(coupon.getEndDate()))) {
                throw new RuntimeException("Coupon is expired or not yet valid.");
            }

            if (totalAmount < coupon.getMinOrderValue()) {
                throw new RuntimeException("Order total (" + totalAmount + ") is less than minimum requirement (" + coupon.getMinOrderValue() + ") for this coupon.");
            }

            couponDiscount = coupon.getDiscountAmount();
        }

        //Calculate finalAmount
        double finalAmount = Math.max(totalAmount - couponDiscount, 0.0);

        //Create Order object
        Order order = new Order();
        order.setUser(cart.getUser());
        order.setOrderDate(LocalDateTime.now());
        order.setStatus(OrderStatus.CONFIRMED);
        order.setPaymentMethod(orderRequestDTO.getPaymentMethod());

        String userProfileAddress = cart.getUser().getAddress();
        String inputAddress = orderRequestDTO.getDeliveryAddress();
        String finalAddress;

        if (userProfileAddress != null && !userProfileAddress.trim().isEmpty()) {
            finalAddress = userProfileAddress;
        } else if (inputAddress != null && !inputAddress.trim().isEmpty()) {
            finalAddress = inputAddress;
        } else {
            throw new RuntimeException("Delivery address is required.");
        }

        order.setDeliveryAddress(finalAddress);
        order.setCoupon(coupon);
        order.setTotalAmount(totalAmount);
        order.setCouponDiscount(couponDiscount);
        order.setFinalAmount(finalAmount);

        Order savedOrder = orderRepository.save(order);

        //CartItem => OrderDetail
        List<OrderDetail> orderDetails = cartItems.stream()
                .map(item -> {
                    OrderDetail detail = new OrderDetail();
                    detail.setOrder(savedOrder);
                    detail.setProduct(item.getProduct());
                    detail.setQuantity(item.getQuantity());
                    detail.setUnitPrice(item.getProduct().getPrice());
                    detail.setTotalPrice(item.getProduct().getPrice() * item.getQuantity());
                    return detail;
                })
                .collect(Collectors.toList());

        orderDetailRepository.saveAll(orderDetails);

        //Clear ONLY selected items
        cartItemRepository.deleteAll(cartItems);

        savedOrder.setOrderDetails(new HashSet<>(orderDetails));
        return orderMapper.toResponseDTO(savedOrder);
    }


    @Override
    public List<OrderResponseDTO> getOrdersByUser(Long userId) {
        return orderRepository.findByUser_IdUser(userId)
                .stream()
                .map(orderMapper::toResponseDTO)
                .collect(Collectors.toList());
    }

    @Override
    public OrderResponseDTO getOrderById(Long id) {

        return orderRepository.findById(id)
                .map(orderMapper::toResponseDTO)
                .orElseThrow(() -> new RuntimeException("Order not found"));
    }

    @Override
    public List<OrderResponseDTO> getAllOrders() {
        List<Order> orders = orderRepository.findAll();

        return orders.stream()
                .map(orderMapper::toResponseDTO)
                .collect(Collectors.toList());
    }

    @Override
    public OrderResponseDTO updateOrderStatus(Long orderId, OrderStatus newStatus) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new RuntimeException("Order not found with id: " + orderId));

        order.setStatus(newStatus);
        Order updatedOrder = orderRepository.save(order);

        return orderMapper.toResponseDTO(updatedOrder);
    }
}