package encryption;

public class CannotPerformOperationException extends Exception {
    public CannotPerformOperationException(String message) {
        super(message);
    }
}