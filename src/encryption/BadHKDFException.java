package encryption;

public class BadHKDFException extends Exception {
    public BadHKDFException(String message) {
        super(message);
    }
}