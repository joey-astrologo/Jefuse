/********************
 * Written by Giuseppe Astrologo
 * 
 * Allows you to encrypt and decrypt data interchangeably on both Java and PHP.
 * I needed to write this to read encrypted data from a MySQL database that my website inserts data into.
 * 
 * The original DefusePHP was written by Taylor Hornby and Scott Arciszewski
 * https://github.com/defuse/php-encryption
 * 
 */

/*
 * ORIGINAL DISCLAIMER FROM PHP SOURCE
 * 
 * PHP Encryption Library
 * Copyright (c) 2014-2015, Taylor Hornby
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


package encryption;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;

public class Encryption {

    // Ciphertext format: [____HMAC____][____IV____][____CIPHERTEXT____].

    /* DO NOT CHANGE THESE CONSTANTS!
     *
     * We spent *weeks* testing this code, making sure it is as perfect and
     * correct as possible. Are you going to do the same after making your
     * changes? Probably not. Besides, any change to these constants will break
     * the runtime tests, which are extremely important for your security.
     * You're literally millions of times more likely to screw up your own
     * security by changing something here than you are to fall victim to an
     * 128-bit key brute-force attack. You're also breaking your own
     * compatibility with future updates to this library, so you'll be left
     * vulnerable if we ever find a security bug and release a fix.
     *
     * So, PLEASE, do not change these constants.
     */
    
    
    private static final String CIPHER_METHOD = "AES/CBC/PKCS5Padding";
    private static final int KEY_BYTE_SIZE = 16;
    private static final String HASH_FUNCTION = "HmacSHA256";
    private static final int MAC_BYTE_SIZE = 32;
    private static final String ENCRYPTION_INFO = "DefusePHP|KeyForEncryption";
    private static final String AUTHENTICATION_INFO = "DefusePHP|KeyForAuthentication";

    /****************************
     * Translation of the hashing function from PHP Generate a keyed hash value
     * using the Mac method
     * 
     * @param byte[] ciphertext
     * @param byte[] akey
     * @return byte[]
     * 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private static byte[] hash_hmac(byte[] ciphertext, byte[] key) throws InvalidKeyException {
        SecretKey secretKey = new SecretKeySpec(key, HASH_FUNCTION);
        Mac mac = null;
        //Don't change hash function and then this won't throw any exceptions!
        try {
            mac = Mac.getInstance(HASH_FUNCTION);
        } catch(NoSuchAlgorithmException e) {}
        
        mac.init(secretKey);
        return mac.doFinal(ciphertext);
    }

    /**
     * Use HKDF to derive multiple keys from one.
     * http://tools.ietf.org/html/rfc5869
     * 
     * @param byte[] ikm Initial Keying Material
     * @param int length How many bytes?
     * @param string
     *            info What sort of key are we deriving?
     * @param string
     *            salt
     * @return string
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws BadLengthException
     * @throws BadHKDFException
     */
    private static byte[] HKDF(byte[] ikm, int length, String info, String salt) throws InvalidKeyException, CannotPerformOperationException {
        int digestLength = MAC_BYTE_SIZE;
        
        if (length < 0 || length > 255 * digestLength) {
            throw new InvalidKeyException("Length of second parameter is out of range (0 <= length > 8,160).");
        }
        //If salt is empty or null, then set to a string of HashLen zeroes
        if (salt == null || salt.length() <= 0) {
            salt = new String(new char[digestLength]).replace("\0", "\u0000");
        }

        byte[] prk = hash_hmac(ikm, salt.getBytes());

        byte[] t = new byte[0];
        byte[] lastBlock = new byte[0];

        int blockIndex = 1;

        for (blockIndex = 1; t.length < length; ++blockIndex) {
            lastBlock = ArrayUtils.addAll(lastBlock, info.getBytes());
            lastBlock = ArrayUtils
                    .addAll(lastBlock, (byte[]) (Character
                            .toString((char) blockIndex).getBytes()));

            lastBlock = hash_hmac(lastBlock, prk);

            t = ArrayUtils.addAll(t, lastBlock);
        }

        byte[] orm = ArrayUtils.subarray(t, 0, length);

        if (orm.length <= 0) {
           throw new CannotPerformOperationException("Could not retrieve first " + length + " octets of T.");
        }
        return orm;
    }

    /**
     * 
     * Encrypts a message. plaintext is the message to encrypt. keyString is the
     * encryption key, a value generated by createNewRandomKey().
     * 
     * @param string
     *            plaintext
     * @param string
     *            keyString
     * @return string
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws CannotPerformOperationException 
     */
    public static String encrypt(String plainText, String keyString) throws InvalidKeyException, CannotPerformOperationException {
        byte[] output = new byte[1];
        byte[] key = Base64.decodeBase64(keyString.getBytes());
        byte[] ekey = HKDF(key, KEY_BYTE_SIZE, ENCRYPTION_INFO, null);

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[KEY_BYTE_SIZE];
        random.nextBytes(iv);

        byte[] ciphertext = ArrayUtils.addAll(iv, plainEncrypt(plainText.getBytes(), ekey, iv));

        byte[] akey = HKDF(key, KEY_BYTE_SIZE, AUTHENTICATION_INFO, null);
        byte[] auth = hash_hmac(ciphertext, akey);

        output = ArrayUtils.addAll(auth, ciphertext);
        
        return new String(Base64.encodeBase64(output));
    }

    /**
     * Decrypts a ciphertext. cipherString is the ciphertext to decrypt.
     * keyString is the key that the ciphertext was encrypted with.
     * 
     * @param string
     *            cipherString
     * @param string
     *            keyString
     * @return String
     * @throws CannotPerformOperationException 
     * @throws InvalidKeyException 
     * @throws InvalidCiphertextException 
     */
    public static String decrypt(String cipherString, String keyString) throws InvalidKeyException, CannotPerformOperationException, InvalidCiphertextException {
        byte[] plaintext = new byte[0];
        byte[] ciphertext = Base64.decodeBase64(cipherString.getBytes());
        byte[] key = Base64.decodeBase64(keyString.getBytes());
        // Extract the HMAC from the front of the ciphertext.
        if (ciphertext.length <= MAC_BYTE_SIZE) {
            throw new CannotPerformOperationException("Ciphertext is too short.");
        }

        byte[] hmac = ArrayUtils.subarray(ciphertext, 0, MAC_BYTE_SIZE);
        if (hmac.length <= 0) {
            throw new CannotPerformOperationException("HMAC is missing.");
        }

        ciphertext = ArrayUtils.subarray(ciphertext, MAC_BYTE_SIZE, ciphertext.length);
        if (ciphertext.length <= 0) {
            throw new CannotPerformOperationException("Ciphertext is missing");
        }

        byte[] akey = HKDF(key, KEY_BYTE_SIZE, AUTHENTICATION_INFO, "");
        if(verifyHMAC(hmac, ciphertext, akey)) {
            byte[] ekey = HKDF(key, KEY_BYTE_SIZE, ENCRYPTION_INFO, "");

            int ivSize = KEY_BYTE_SIZE;

            if (ciphertext.length <= ivSize) {
                throw new CannotPerformOperationException("Ciphertext shorter than IV.");
            }
            byte[] iv = ArrayUtils.subarray(ciphertext, 0, ivSize);
            if (iv.length <= 0) {
                throw new CannotPerformOperationException("IV NULL");
            }
            ciphertext = ArrayUtils.subarray(ciphertext, ivSize, ciphertext.length);
            if (ciphertext.length <= 0) {
                throw new CannotPerformOperationException("Ciphertext NULL");
            }
            plaintext = plainDecrypt(ciphertext, ekey, iv);

            return new String(plaintext, StandardCharsets.UTF_8);
        }
        else {
            throw new InvalidCiphertextException("Integrity check failed.");
        }
    }

    /**
     * Never call this method directly!
     * 
     * Unauthenticated message deryption.
     * 
     * @param byte[] ciphertext
     * @param byte[] key
     * @param byte[] iv
     * @return byte[]
     */
    private static byte[] plainDecrypt(byte[] ciphertext, byte[] key, byte[] iv) {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec secret = new SecretKeySpec(key, "AES");
        Cipher cipher;
        byte[] decrypted = null;
        
        try {
            cipher = Cipher.getInstance(CIPHER_METHOD);
            cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
            decrypted = cipher.doFinal(ciphertext);
        }
        catch(NoSuchAlgorithmException e) {} 
        catch (NoSuchPaddingException e) {e.printStackTrace();} 
        catch (InvalidKeyException e) {e.printStackTrace();} 
        catch (InvalidAlgorithmParameterException e) {e.printStackTrace();} 
        catch (IllegalBlockSizeException e) {e.printStackTrace();} 
        catch (BadPaddingException e) {e.printStackTrace();}
        
        return decrypted;
    }

    /**
     * Never call this method directly!
     * 
     * Unauthenticated message encryption.
     * 
     * @param byte[] text
     * @param byte[] key
     * @param byte[] iv
     * @return byte[]
     */
    private static byte[] plainEncrypt(byte[] text, byte[] key, byte[] iv) {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher;
        byte[] encrypted = null;
        
        try {
            cipher = Cipher.getInstance(CIPHER_METHOD);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
            encrypted = cipher.doFinal(text);
        } 
        catch(NoSuchPaddingException e) {e.printStackTrace();}  
        catch (NoSuchAlgorithmException e) {e.printStackTrace();}  
        catch (InvalidKeyException e) {e.printStackTrace();}  
        catch (InvalidAlgorithmParameterException e) {e.printStackTrace();}  
        catch (IllegalBlockSizeException e) {} catch (BadPaddingException e) {e.printStackTrace();} 
        
        return encrypted;
    }

    /**
     * Use this to generate a random encryption key.
     * 
     * @return string
     */
    public static String createNewRandomKey() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[KEY_BYTE_SIZE];
        random.nextBytes(iv);
        return new String(Base64.encodeBase64(iv), StandardCharsets.UTF_8);
    }
    /**
     * Verify a HMAC 
     * timing safe
     * 
     * @param byte[] correctHMAC HMAC binary
     * @param byte[] message Ciphertext (raw binary)
     * @param byte[] key Authentication key (raw binary)
     * 
     * @return boolean
     * @throws InvalidKeyException
     */
    private static boolean verifyHMAC(byte[] correctHMAC, byte[] message, byte[] key) {
        byte[] messageHMAC = null;
        try {
            messageHMAC = hash_hmac(message, key);
        } catch(InvalidKeyException e) {e.printStackTrace();}
        
        if (correctHMAC.length != messageHMAC.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < correctHMAC.length; i++) {
          result |= correctHMAC[i] ^ messageHMAC[i];
        }
        return result == 0;
    }
}
