package test;

import java.security.InvalidKeyException;

import encryption.CannotPerformOperationException;
import encryption.Encryption;

public class Demo {

    public static void main(String[] args) {
        // TODO Auto-generated method stub
       String secretKey = Encryption.createNewRandomKey();
       
       String plainText = "Typical Chinese bullshit, always going after the donuts!";
       String encryptedText = null;
       try{
           encryptedText = Encryption.encrypt(plainText, secretKey);
       }
       catch(InvalidKeyException e) {e.printStackTrace();}
       catch(CannotPerformOperationException e) {e.printStackTrace();}
       catch(Exception e) {e.printStackTrace();}
       
       String decryptedText = null;;
       try {
           decryptedText = Encryption.decrypt(encryptedText, secretKey);
       }
       catch(InvalidKeyException e) {e.printStackTrace();}
       catch(CannotPerformOperationException e) {e.printStackTrace();}
       catch(Exception e) {e.printStackTrace();}
       
       System.out.println("Secret Key: " + secretKey);
       System.out.println(plainText);
       System.out.println(encryptedText);
       System.out.println(decryptedText);
       
    }

}
