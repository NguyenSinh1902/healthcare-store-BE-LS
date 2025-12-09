package iuh.fit.se.exceptions;

public class NotFoundException extends RuntimeException {
    public NotFoundException(Long id) {
        super("Resource not found with id: " + id);
    }
    public NotFoundException(String message) {
        super(message);
    }
}
