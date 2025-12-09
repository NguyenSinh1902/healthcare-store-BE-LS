package iuh.fit.se.exceptions;

import java.util.List;
import java.util.Map;

public class ValidationException extends RuntimeException {
    private final List<Map<String, String>> errors;

    public ValidationException(List<Map<String, String>> errors) {
        this.errors = errors;
    }

    public List<Map<String, String>> getErrors() {
        return errors;
    }
}
