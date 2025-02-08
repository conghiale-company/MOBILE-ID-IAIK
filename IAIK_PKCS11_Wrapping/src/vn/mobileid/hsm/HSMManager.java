/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package vn.mobileid.hsm;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.OperatorCreationException;

/**
 *
 * @author Tan_Hung
 */
public interface HSMManager {
    //connect to hsm
    public Token connectHSM() throws TokenException;

    //disconnect from hsm
    public boolean disconnectHSM();
    
    public String genKeyPair(HSMManagerImp.KeyType keyType, int size, StringBuilder stringBuilder, String keyName) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException;

    public AESSecretKey genAESSecretKey(int paramInt, String paramString) throws TokenException;

    public KeyPair genKeyPair(HSMManagerImp.KeyType keyType, int size, String keyLabel) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException;

    public Session getSession() throws TokenException;

    public byte[] genCSR(HSMManagerImp.KeyType paramKeyType, String keyLabel, StringBuilder paramStringBuilder) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException;

    public String gen_CSR(HSMManagerImp.KeyType keyType, String keyLabel, StringBuilder builder) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException;
    
    public AESSecretKey findAESSecretKey(String paramString) throws TokenException;
    
    public ECDSAPrivateKey findECDSAPrivateKey(String keyLabel) throws TokenException;

    public PrivateKey findPrivateKey(String keyLabel, String keyType) throws TokenException;

    public PublicKey findPublicKey(String keyLabel, String keyType) throws TokenException;
    
    public void checkAvailableSlot() throws TokenException;
    
    public byte[] sign(long pkcs11MechanismCode, byte[] plaintext, Key privateKey) throws PKCS11Exception, TokenException, UnsupportedEncodingException;
    
    public byte[] signHash(byte[] hash, byte[] keyWrapped, String AESKeyName) throws TokenException, GeneralSecurityException, UnsupportedEncodingException, IOException, Exception;
    
    public byte[] unWrapKeyAES(byte[] paramArrayOfbyte, String paramString) throws TokenException;

    public Key unWrapKey(byte[] paramArrayOfbyte, Key paramKey, String paramString1, String paramString2) throws TokenException;
    
    public String importKey(String paramString, Object paramObject, HSMManagerImp.KeyType paramKeyType, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) throws TokenException;
    
    public byte[] unWrapKey(byte[] secretKeyWrapped, String hsmKeyID) throws TokenException;
    
    public AESSecretKey genAESSecretKey(int size) throws TokenException;

    public AESSecretKey genAESSecretKey(String keyID, int size, boolean isToken) throws TokenException;
    
    public byte[] wrapKey(AESSecretKey scSysKey, String hsmKeyID) throws TokenException;

    public byte[] wrapKey(Key wrappedKey, Key wrappingKey, long mode, byte[] iv) throws TokenException;
    
    public Key unWrapKey(byte[] secretKeyWrapped, Key wrappingKey, long mode, byte[] iv, Long keyType, String keyID, boolean isToken) throws TokenException;

    public Key unWrapECDSAKey(byte[] secretKeyWrapped, Key wrappingKey, long mode, byte[] iv, Long keyType, String keyID) throws TokenException;
    
    public boolean deleteKeyPair(KeyPair keyPair) throws TokenException;
    
//    public KeyPair genECDSAKeyPair(String keyID, String keyLabel, final ASN1ObjectIdentifier curveId) throws TokenException;
    
    public KeyPair genECDSAKeyPair(int size, String KeyLabel) throws TokenException;
    
    public KeyPair genRSAKeyPair(int size, String KeyLabel) throws TokenException;

    public int removeObjects(String keyID, String keyLabel) throws TokenException;

    public String signJWTByEDCSA(String header, String payload, byte[] keyWrapped, String AESKeyName) throws Exception;

    public boolean verifiedJWTByEDCSA(String jwt, byte[] keyWrapped, String AESKeyName) throws Exception;
}
