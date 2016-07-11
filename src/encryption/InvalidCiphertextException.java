package encryption;

public class InvalidCiphertextException extends Exception {
    public InvalidCiphertextException(String message) {
        super(message);
    }
}
