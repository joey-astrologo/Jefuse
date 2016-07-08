/********************
 * 	Written by Giuseppe Astrologo
 * 
 *  Allows you to encrypt and decrypt data interchangeably on both Java and PHP.
 *  I needed to write this to read encrypted data from a MySQL database that my website inserts data into.
 * 
 *  The original DefusePHP was written by Taylor Hornby and Scott Arciszewski
 * 	https://github.com/defuse/php-encryption
 * 
 */

package encryption;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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
	
	private static final String CIPHER_METHOD = "AES/CBC/PKCS5Padding";
	private static final int KEY_BYTE_SIZE = 16;
	private static final String HASH_FUNCTION = "HmacSHA256";
	private static final int MAC_BYTE_SIZE = 32;
	private static final String ENCRYPTION_INFO = "DefusePHP|KeyForEncryption";
	private static final String AUTHENTICATION_INFO = "DefusePHP|KeyForAuthentication";
	
	/****************************
	 * Translation of the hashing function from PHP
	 * Generate a keyed hash value using the Mac method
	 * 
	 * @param byte[] ciphertext
	 * @param byte[] akey
	 * @return byte[]
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private static byte[] hash_hmac(byte[] ciphertext, byte[] akey) throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKey secretKey = null;

		byte[] keyBytes = akey;
		secretKey = new SecretKeySpec(keyBytes, HASH_FUNCTION);

		Mac mac = Mac.getInstance(HASH_FUNCTION);
		mac.init(secretKey);

		byte[] text = ciphertext;

		return mac.doFinal(text);
	}
	/**
     * Use HKDF to derive multiple keys from one.
     * http://tools.ietf.org/html/rfc5869
     * 
     * @param byte[] ikm Initial Keying Material
     * @param int length How many bytes?
     * @param string info What sort of key are we deriving?
     * @param string salt
     * @return string
     * 
     * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws BadLengthException
	 * @throws BadHKDFException
     */
	private static byte[] HKDF(byte[] ikm, int length, String info, String salt) throws InvalidKeyException, NoSuchAlgorithmException, BadLengthException, BadHKDFException {
		 int digestLength = MAC_BYTE_SIZE;
		 //TO-DO: MAKE EXCEPTIONS
		 if (length < 0 || length > 255 * digestLength) {
			 throw new BadLengthException("Bad output length requested of HKDF.");
		 }
		 
		 if (salt.length() <= 0) {
			 salt = new String(new char[digestLength]).replace("\0", "\u0000");
	     }
		 
		 byte[] prk = hash_hmac(ikm, salt.getBytes());
		 
		 byte[] t = new byte[0];
	     byte[] lastBlock = new byte[0];
	     
	     int blockIndex = 1;
	     
	     for (blockIndex = 1; t.length < length; ++blockIndex) {
	    	 lastBlock = ArrayUtils.addAll(lastBlock, info.getBytes());
	    	 lastBlock = ArrayUtils.addAll(lastBlock, (byte[])(Character.toString((char) blockIndex).getBytes()));
	    	 
	    	 lastBlock = hash_hmac(lastBlock, prk);
	        
	    	 t = ArrayUtils.addAll(t, lastBlock);
	     }
	     
	     byte[] orm = ArrayUtils.subarray(t, 0, length);
	     
	     if (orm.length <= 0) {
	    	 throw new BadHKDFException("Bad output generated by HKDF.");
	     }
	     return orm;
	}
	/**
    * 
    * Encrypts a message.
    * plaintext is the message to encrypt.
    * keyString is the encryption key, a value generated by createNewRandomKey().
    * 
    * @param string plaintext
    * @param string keyString
    * @return string
    */
	public static String encrypt(String plainText, String keyString) {
		byte[] output = new byte[1];
		try {
			byte[] key = Base64.decodeBase64(keyString.getBytes());
			byte[] ekey = HKDF(key, KEY_BYTE_SIZE, ENCRYPTION_INFO, "");
        
			SecureRandom random = new SecureRandom();
			byte[] iv = new byte[KEY_BYTE_SIZE];
			random.nextBytes(iv);
        
			byte[] ciphertext = ArrayUtils.addAll(iv, plainEncrypt(plainText.getBytes(), ekey, iv));
		
			byte[] akey = HKDF(key, KEY_BYTE_SIZE, AUTHENTICATION_INFO, "");
			byte[] auth = hash_hmac(ciphertext, akey);
		
			output = ArrayUtils.addAll(auth, ciphertext);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadHKDFException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return new String(Base64.encodeBase64(output));
	}
	/**
     * Decrypts a ciphertext.
     * cipherString is the ciphertext to decrypt.
     * keyString is the key that the ciphertext was encrypted with.
     * 
     * @param string cipherString
     * @param string keyString
     * @return String
     */
	public static String decrypt(String cipherString, String keyString) {
		byte[] plaintext = new byte[0];
		try {
			byte[] ciphertext = Base64.decodeBase64(cipherString.getBytes());
			byte[] key = Base64.decodeBase64(keyString.getBytes());
			// Extract the HMAC from the front of the ciphertext.
			if (ciphertext.length <= MAC_BYTE_SIZE) {
				throw new ByteLengthException("Ciphertext is too short.");
			}
	    
			byte[] hmac = ArrayUtils.subarray(ciphertext, 0, MAC_BYTE_SIZE);
			if (hmac.length <= 0) {
				throw new ByteLengthException("HMAC length mismatch");
			}
			
			ciphertext = ArrayUtils.subarray(ciphertext, MAC_BYTE_SIZE, ciphertext.length);
			if (ciphertext.length <= 0) {
				throw new ByteLengthException("Ciphertext NULL");
			}
	    
			byte[] akey = HKDF(key, KEY_BYTE_SIZE, AUTHENTICATION_INFO, "");
			//TO-DO vefrifyHmac
			byte[] ekey = HKDF(key, KEY_BYTE_SIZE, ENCRYPTION_INFO, "");
	   
			int ivSize = KEY_BYTE_SIZE;
	    
			if (ciphertext.length <= ivSize) {
				throw new ByteLengthException("Ciphertext shorter than IV.");
			}
			byte[] iv = ArrayUtils.subarray(ciphertext, 0, ivSize);
			if (iv.length <= 0) {
				throw new ByteLengthException("IV NULL");
			}
			ciphertext = ArrayUtils.subarray(ciphertext, ivSize, ciphertext.length);
			if (ciphertext.length <= 0) {
				throw new ByteLengthException("Ciphertext NULL");
			}
			plaintext = plainDecrypt(ciphertext, ekey, iv);
		} catch(BadHKDFException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ByteLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

        return new String(plaintext, StandardCharsets.UTF_8);
	}
	 /**
     * Never call this method directly!
     * 
     * Unauthenticated message deryption.
     * 
     * @param byte[] ciphertext
     * @param byte[] key
     * @param byte[] iv
     * @return string
     *  
     * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
     */
	private static byte[] plainDecrypt(byte[] ciphertext, byte[] key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		SecretKeySpec secret = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);

		return cipher.doFinal(ciphertext);
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
     * 
     * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
     */
	private static byte[] plainEncrypt(byte[] text, byte[] key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException  {
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher;
		
		cipher = Cipher.getInstance(CIPHER_METHOD);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
		
		return cipher.doFinal(text);
	}
	/**
     * Use this to generate a random encryption key.
     * 
     * @return string
     */
	public static String createNewRandomKey()
    {
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[KEY_BYTE_SIZE];
		random.nextBytes(iv);
        return new String(Base64.encodeBase64(iv), StandardCharsets.UTF_8);
    }
}