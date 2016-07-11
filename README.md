# Jefuse


About
------------

This is a Java translation of defuse's php-encryption library available [here](https://github.com/defuse/php-encryption).
Please refer to their page for a more detailed description.

How to use
------------

This library is pretty simple to use. Just make a secret key using the provided function, keep that key to encrypt and decrypt
your data. Exceptions must be caught in order for this library to function correctly! I tried to only allow exceptions that the 
user could encounter as long as the default constants aren't played around with.

Example
------------
Code:
~~~java
String secretKey = Encryption.createNewRandomKey();
       
String plainText = "Cool uncle Stu balls.";
String encryptedText = Encryption.encrypt(plainText, secretKey);
String decryptedText = Encryption.decrypt(encryptedText, secretKey);
       
System.out.println("Secret Key: " + secretKey);
System.out.println(plainText);
System.out.println(encryptedText);
System.out.println(decryptedText);
~~~
Output:
    
    Secret Key: +IGfyaa3jQzXo3JOi7WXRg==
    Cool uncle Stu balls.
    PgenoeWGzf6nMIy+PUEMPObPeeiMp0e2TxbS69ttEhtSDLo2AReSu7/VQ3hPsuqXxg2apHMXH0ggoySZHrgkXCTGKNqbed1IRcui0dNuZ/A=
    Cool uncle Stu balls.
