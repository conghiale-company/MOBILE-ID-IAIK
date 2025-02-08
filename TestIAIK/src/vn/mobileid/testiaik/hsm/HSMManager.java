package vn.mobileid.testiaik.hsm;

import java.io.UnsupportedEncodingException;

import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface HSMManager {

    //connect to hsm
    public Token connectHSM() throws TokenException;

    //disconnect from hsm
    public boolean disconnectHSM();

    public String encryptDataWithKeyID(String plaintext, String KeyID) throws PKCS11Exception, TokenException, UnsupportedEncodingException;

    public byte[] encryptDataWithKeyID(byte[] data, String KeyID) throws TokenException, UnsupportedEncodingException;

    public String decryptDataWithKeyID(String encText, String KeyID) throws PKCS11Exception, TokenException;

    public byte[] decryptDataWithKeyID(byte[] dataEncoded, String KeyID) throws TokenException;

    public byte[] unWrapKey(byte[] secretKeyWrapped, String hsmKeyID) throws TokenException;

    public byte[] genAndWrapAESSecretKey(int size, String hsmKeyID) throws Exception;
    

    public AESSecretKey genAESSecretKey(int size) throws TokenException;

    public AESSecretKey genAESSecretKey(String keyID, int size, boolean isToken) throws TokenException;

    public byte[] wrapKey(AESSecretKey scSysKey, String hsmKeyID) throws TokenException;

    public byte[] wrapKey(Key wrappedKey, Key wrappingKey, long mode, byte[] iv) throws TokenException;

    public boolean hasKeyID(String keyID) throws TokenException;
    
    public byte[] signWithKeyID(long pkcs11MechanismCode, byte[] plaintext, String KeyID) throws PKCS11Exception, TokenException, UnsupportedEncodingException, HSMException;

    public byte[] signWithPrivateKey(long pkcs11MechanismCode, byte[] plaintext, Key privateKey) throws PKCS11Exception, TokenException, UnsupportedEncodingException;

    public byte[] signWithPrivateKey20210224(long pkcs11MechanismCode, byte[] plaintext, RSAPrivateKey privateKey) throws PKCS11Exception, TokenException, UnsupportedEncodingException;

    public RSAPrivateKey getPrivateKeyWithKeyID(String keyId) throws TokenException;

    public Key getKeyWithKeyID(String keyId) throws TokenException;

    public Key unWrapKey(byte[] secretKeyWrapped, Key wrappingKey, long mode, byte[] iv, Long keyType, String keyID, boolean isToken) throws TokenException;

    public boolean deleteKeyPair(KeyPair keyPair) throws TokenException;

    public boolean deleteKey(Key key) throws TokenException;
    
    public List<ECDSAPrivateKey> getECKeyByID(String keyID) throws Exception;
    public List<ECDSAPrivateKey> getECKeyByLabel(String keyLabel) throws Exception;
    public List<ECDSAPublicKey> getPublicECKeyByID(String keyID) throws Exception;
    public List<ECDSAPublicKey> getPublicECKeyByLabel(String keyLabel) throws Exception;
    public List<ECDSAPrivateKey> listECKeys() throws Exception;
    
    public byte[] sign(long pkcs11MechanismCode, byte[] plaintext, Key privateKey)
            throws PKCS11Exception, TokenException, UnsupportedEncodingException;
    
    public boolean idExists(String keyID)throws TokenException;
    public boolean labelExists(String keyLabel)throws TokenException;
    public KeyPair genECDSAKeyPair(String keyID, String keyLabel, final ASN1ObjectIdentifier curveId) throws TokenException;
    
    public int removeObjects(String keyID, String keyLabel)throws TokenException;
    
    public KeyPair GenerateRSAKeyPair(String keyID, int Keylength, int publicExponent)
            throws NumberFormatException, NoSuchAlgorithmException, InvalidKeySpecException, TokenException;
}
