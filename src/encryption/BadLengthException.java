package encryption;

public class BadLengthException extends Exception {
    public BadLengthException(String message) {
        super(message);
    }
}