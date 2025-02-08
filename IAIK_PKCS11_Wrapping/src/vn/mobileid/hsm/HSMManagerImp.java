/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package vn.mobileid.hsm;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.concurrent.locks.ReentrantLock;

// Update 2024.01.18
import java.io.ByteArrayOutputStream;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.xml.bind.DatatypeConverter;
import iaik.pkcs.pkcs11.Mechanism;

import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Module;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateParsingException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import javax.xml.bind.DatatypeConverter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import sun.security.util.DerOutputStream;
import sun.security.x509.AlgorithmId;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author Tan_Hung
 */
public class HSMManagerImp implements HSMManager {
//    Start_test
    private PublicKey publicKey;
    private String uuidTest;

    private static final Logger LOG = LogManager.getLogger(HSMManagerImp.class);

    private boolean login;

    private static HSMManager instance = null;

    public HSMFunction hsmFunction;

    private String passsword;

    private Session sessionLogin;

    private int slotNumber;

    private Map<String, PrivateKey> keyCache = new HashMap<>();

    private static ReentrantLock lock = new ReentrantLock();

    private AESSecretKey aes;

    public HSMFunction getHsmFunction() {
        return hsmFunction;
    }

    public HSMManagerImp(String pkcs11LibName, String pkcs11Wrapper, int slot, String password) throws IOException, TokenException {
        hsmFunction = new HSMFunction();
        hsmFunction.loadDll(pkcs11LibName, pkcs11Wrapper);
        this.slotNumber = slot;

        this.login = false;

        this.passsword = password;
    }

    @SuppressWarnings("unused")
    private void init(String dllName, String wrapper) throws Throwable {
        String pkcs11Wrapper = wrapper;
        hsmFunction.loadDll(dllName, pkcs11Wrapper);
    }

    public static HSMManager getInstance(String pkcs11LibName, String pkcs11Wrapper, int slot, String password) {
        lock.lock();
        try {
            instance = new HSMManagerImp(pkcs11LibName, pkcs11Wrapper, slot, password);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            lock.unlock();
        }
        return instance;
    }

    public boolean loginHSM() throws TokenException {
        // TODO Auto-generated method stub
        if (isLogin()) {
            return true;
        }

        lock.lock();
        if (isLogin()) {
            lock.unlock();
            return true;
        }

        try {
            sessionLogin = hsmFunction.openSession(slotNumber);
            login = hsmFunction.login(sessionLogin, passsword);
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
            throw e;
        } finally {
            lock.unlock();
        }
        return login;
    }

    public boolean logoutHSM() throws TokenException {
        // TODO Auto-generated method stub
        boolean status1 = hsmFunction.logout(sessionLogin);
        if (status1) {
            login = false;
            sessionLogin.closeSession();
            return true;
        } else {
            return false;
        }
    }

    private boolean isLogin() {
        return login;
    }

    @Override
    public Token connectHSM() throws TokenException {
        // TODO Auto-generated method stub
        Token tokenInfo = hsmFunction.getToken();
        if (tokenInfo == null) {
            hsmFunction.connectToken(slotNumber);
        }

        return hsmFunction.getToken();
    }

    @Override
    public boolean disconnectHSM() {
        boolean res = false;
        try {
            res = logoutHSM();
        } catch (TokenException e) {
            e.printStackTrace();
        } finally {
            if (hsmFunction.disconnectToken()) {
                instance = null;
            }
        }

        return res;
    }

    @Override
    public byte[] unWrapKeyAES(byte[] paramArrayOfbyte, String paramString) throws TokenException {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public String importKey(String paramString, java.lang.Object paramObject, KeyType paramKeyType, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) throws TokenException {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public String signJWTByEDCSA(String header, String payload, byte[] keyWrapped, String AESKeyName) throws Exception {
        ensureLoggedIn();

        String dataToBeSign = hsmFunction.base64UrlEncode(header) + "." + hsmFunction.base64UrlEncode(payload);
        byte[] hashedBytes = hsmFunction.hashDataWithSha256(dataToBeSign.getBytes("UTF-8"));

        byte[] decodedPrivate = Base64.getDecoder().decode(keyWrapped);
        String jsonString = new String(decodedPrivate, StandardCharsets.UTF_8);
        JsonNode rootNode = parseJson(jsonString);
        String keyType = rootNode.get("KeyAlg").asText();
        String keyName = rootNode.get("KeyName").asText();
        String base64Csr1 = rootNode.get("PrivateKey").asText();
        LOG.debug("Founded Key Type: " + keyType);

        byte[] signature;
        if (aes == null) {
            aes = findAESSecretKey(AESKeyName);
            validateAESSecretKey(aes, AESKeyName);
            PrivateKey privateKey = getPrivateKeyFromCacheOrGenerate(keyName, keyType, base64Csr1, aes);
            signature = signHashBasedOnKeyType(hashedBytes, keyType, privateKey);
        } else {
            validateAESSecretKey(aes, AESKeyName);
            PrivateKey privateKey = getPrivateKeyFromCacheOrGenerate(keyName, keyType, base64Csr1, aes);
            signature = signHashBasedOnKeyType(hashedBytes, keyType, privateKey);
        }

        String res = "";
        if (signature != null) {
            System.out.println("JWT signature created successfully");

//            Encode the signature to Base64
            String encodedSignature = hsmFunction.base64UrlEncode(signature);
            String jwt = dataToBeSign + "." + encodedSignature;
            res = Objects.equals(jwt, "") ? "Create jwt unsuccessfully" : jwt;
        } else {
            System.out.println("JWT signature could not be created");
        }

        return res;
    }   
    
    @Override
    public boolean verifiedJWTByEDCSA(String jwt, byte[] keyWrapped, String AESKeyName) throws Exception {
        // Split JWT into parts: Header, Payload, Signature
        String[] jwtParts = jwt.split("\\.");
        String header = jwtParts[0];
        String payload = jwtParts[1];
        String signature = jwtParts[2];

        byte[] decodedPrivate = Base64.getDecoder().decode(keyWrapped);
        String jsonString = new String(decodedPrivate, StandardCharsets.UTF_8);
        JsonNode rootNode = parseJson(jsonString);
        String keyType = rootNode.get("KeyAlg").asText();
        String keyName = rootNode.get("KeyName").asText();
        LOG.debug("Founded Key Type: " + keyType);

        PublicKey publicKey;
        if (aes == null) {
            aes = findAESSecretKey(AESKeyName);
            validateAESSecretKey(aes, AESKeyName);
            publicKey = findPublicKey(keyName, keyType);
        } else {
            validateAESSecretKey(aes, AESKeyName);
            publicKey = findPublicKey(keyName, keyType);
        }

        Session session = this.hsmFunction.openSession(this.slotNumber);
        return this.hsmFunction.verifySignature(session, publicKey, header, payload, Base64.getUrlDecoder().decode(signature));
    }

    public enum KeyType {
        RSA, ECDSA, AES;
    }

    public class RSAKeyImporter {

        public String importKey(String keyId, RSAPrivateKey privateKey) throws TokenException {
            if (!HSMManagerImp.this.isLogin()) {
                HSMManagerImp.this.loginHSM();
            }
            if (HSMManagerImp.this.isLogin()) {
                Session session = HSMManagerImp.this.hsmFunction.openSession(HSMManagerImp.this.slotNumber);
                String response = HSMManagerImp.this.hsmFunction.importKey(keyId, privateKey, session);
                return response;
            }
            return null;
        }

        public String importKey(String keyId, byte[] prExp, byte[] modulus) throws TokenException {
            if (!HSMManagerImp.this.isLogin()) {
                HSMManagerImp.this.loginHSM();
            }
            if (HSMManagerImp.this.isLogin()) {
                Session session = HSMManagerImp.this.hsmFunction.openSession(HSMManagerImp.this.slotNumber);
                String response = HSMManagerImp.this.hsmFunction.importKey(keyId, prExp, modulus, session);
                return response;
            }
            return null;
        }
    }

    public class ECDSAKeyImporter {

        public String importKey(String keyId, ECDSAPrivateKey privateKey) throws TokenException {
            if (!HSMManagerImp.this.isLogin()) {
                HSMManagerImp.this.loginHSM();
            }
            if (HSMManagerImp.this.isLogin()) {
                Session session = HSMManagerImp.this.hsmFunction.openSession(HSMManagerImp.this.slotNumber);
                String response = HSMManagerImp.this.hsmFunction.importKey(keyId, privateKey, session);
                return response;
            }
            return null;
        }
    }

    public class AESSecretKeyImporter {

        public String importKey(String keyId, Key privateKey) throws TokenException {
            if (!HSMManagerImp.this.isLogin()) {
                HSMManagerImp.this.loginHSM();
            }
            if (HSMManagerImp.this.isLogin()) {
                Session session = HSMManagerImp.this.hsmFunction.openSession(HSMManagerImp.this.slotNumber);
                String response = HSMManagerImp.this.hsmFunction.importKey(keyId, privateKey, session);
                return response;
            }
            return null;
        }
    }

    public String importKey(String keyId, Object privateKey, KeyType keyType, byte[] prExp, byte[] modulus) throws TokenException {
        if (keyType == KeyType.RSA && privateKey instanceof RSAPrivateKey) {
            RSAKeyImporter rsaKeyImporter = new RSAKeyImporter();
            return rsaKeyImporter.importKey(keyId, (RSAPrivateKey) privateKey);
        }
        if (keyType == KeyType.ECDSA && privateKey instanceof Key) {
            ECDSAKeyImporter ecdsaKeyImporter = new ECDSAKeyImporter();
            return ecdsaKeyImporter.importKey(keyId, (ECDSAPrivateKey) privateKey);
        }
        if (keyType == KeyType.AES) {
            AESSecretKeyImporter ecdsaKeyImporter = new AESSecretKeyImporter();
            return ecdsaKeyImporter.importKey(keyId, (Key) privateKey);
        }
        throw new IllegalArgumentException("Invalid key type or key object.");
    }

    public byte[] unWrapKey(byte[] secretKeyWrapped, String hsmKeyID) throws TokenException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            RSAPrivateKey privateKey = hsmFunction.getPrivateKeyByID(hsmKeyID, session);
            privateKey.getUnwrap().setBooleanValue(Boolean.TRUE);
            byte[] rawKeyWrapped = hsmFunction.unwrapAESKey(privateKey, secretKeyWrapped, session);
            session.closeSession();
            return rawKeyWrapped;

        } else {
            return null;
        }
    }

    public AESSecretKey genAESSecretKey(int size) throws TokenException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            AESSecretKey response = hsmFunction.genAESKey(size, session);
            return response;
        }
        return null;
    }

    public AESSecretKey genAESSecretKey(int size, String Keyname) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = this.hsmFunction.openSession(this.slotNumber);
            AESSecretKey response = null;
            if (findAESSecretKey(Keyname) == null) {
                response = this.hsmFunction.genAESKey(size, Keyname, session);
            } else {
                throw new IllegalArgumentException("Key name alredy exist");
            }
            return response;
        }
        return null;
    }

    public AESSecretKey genAESSecretKey(String keyID, int size, boolean isToken) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            AESSecretKey response = hsmFunction.genAESKey(keyID, size, session, isToken, true);
            //not close session when crate AES-key
            session.closeSession();
            return response;
        }
        return null;
    }

    public byte[] wrapKey(AESSecretKey scSysKey, String hsmKeyID) throws TokenException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            RSAPublicKey publicKey = hsmFunction.getPublicKeyByID(hsmKeyID, session);
            publicKey.getWrap().setBooleanValue(Boolean.TRUE);
            byte[] rawKeyWrapped = hsmFunction.wrapKey((Key) publicKey, (Key) scSysKey, session);
            session.closeSession();

            return rawKeyWrapped;
        }
        return null;
    }

    public byte[] wrapKey(Key wrappedKey, Key wrappingKey, long mode, byte[] iv) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            Mechanism mechanism = Mechanism.get(mode);
            if (iv != null) {
                mechanism.setParameters(new InitializationVectorParameters(iv));
            }
            byte[] rawKeyWrapped = hsmFunction.wrapKey(wrappingKey, wrappedKey, session, mechanism);
            session.closeSession();
            return rawKeyWrapped;
        }
        return null;
    }

    public byte[] signHash(byte[] hashBytes, Key privateKey) throws TokenException, PKCS11Exception, UnsupportedEncodingException {
        byte[] signature;
        if (privateKey instanceof RSAPrivateKey) {
            signature = signWithPrivateKeyRSA(hashBytes, privateKey);
        } else {
            signature = signWithPrivateKeyEC(hashBytes, privateKey);
        }
        return signature;
    }

    private byte[] signWithPrivateKeyRSA(byte[] plaintext, Key privateKey) throws PKCS11Exception, TokenException, UnsupportedEncodingException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = this.hsmFunction.openSession(this.slotNumber);
            if (privateKey == null) {
                session.closeSession();
                return null;
            }
            long pkcs11MechanismCode = 1L;
            byte[] signed = this.hsmFunction.sign(pkcs11MechanismCode, plaintext, privateKey, session);
            session.closeSession();
            return signed;
        }
        return null;
    }

    private byte[] signWithPrivateKeyEC(byte[] plaintext, Key privateKey) throws PKCS11Exception, TokenException, UnsupportedEncodingException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = this.hsmFunction.openSession(this.slotNumber);
            if (privateKey == null) {
                session.closeSession();
                return null;
            }
            long pkcs11MechanismCode = 4161L;
            byte[] signed = this.hsmFunction.sign(pkcs11MechanismCode, plaintext, privateKey, session);
            session.closeSession();
            return signed;
        }
        return null;
    }

    public Key unWrapKey(byte[] secretKeyWrapped, Key wrappingKey, long mode, byte[] iv, Long keyType, String keyID, boolean isToken) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            Mechanism mechanism = Mechanism.get(mode);
            if (iv != null) {
                mechanism.setParameters(new InitializationVectorParameters(iv));
            }
            // ECDSA
            Key wrappedKey = hsmFunction.unwrapECDSAKey(wrappingKey, secretKeyWrapped, session, mechanism, keyType, keyID, isToken);
            session.closeSession();
            return wrappedKey;

        }
        return null;
    }

    public Key unWrapKey(byte[] secretKeyWrapped, Key wrappingKey, String keyType, String keyID) throws TokenException {
        switch (keyType) {
            case "RSA":
                return unWrapKey(secretKeyWrapped, wrappingKey, 8457L, null, Long.valueOf(0L), keyID, true);
            case "ECDSA":
                return unWrapECDSAKey(secretKeyWrapped, wrappingKey, 8457L, null, Long.valueOf(3L), keyID);
        }
        throw new IllegalArgumentException("Unknown key type: " + keyType);
    }

    public Key unWrapECDSAKey(byte[] secretKeyWrapped, Key wrappingKey, long mode, byte[] iv, Long keyType, String keyID) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = this.hsmFunction.openSession(this.slotNumber);
            Mechanism mechanism = Mechanism.get(mode);
            if (iv != null) {
                mechanism.setParameters((Parameters) new InitializationVectorParameters(iv));
            }
            Key wrappedKey = hsmFunction.unwrapECDSAKey(wrappingKey, secretKeyWrapped, keyID, keyType, keyID, mechanism, session);
            session.closeSession();
            return wrappedKey;
        }
        return null;
    }

    public Key unWrapECDSAKey(byte[] secretKeyWrapped, Key wrappingKey, long mode, byte[] iv, Long keyType, String keyID, boolean isToken) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            Mechanism mechanism = Mechanism.get(mode);
            if (iv != null) {
                mechanism.setParameters(new InitializationVectorParameters(iv));
            }
            Key wrappedKey = hsmFunction.unwrapECDSAKey(wrappingKey, secretKeyWrapped, session, mechanism, keyType, keyID, isToken);
            session.closeSession();
            return wrappedKey;

        } else {
            return null;
        }
    }

    public boolean deleteKeyPair(KeyPair keyPair) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            hsmFunction.deleteKey(keyPair.getPrivateKey(), session);
            hsmFunction.deleteKey(keyPair.getPublicKey(), session);
            session.closeSession();
            return true;
        }
        return false;
    }

    public boolean deleteKey(Key key) throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            hsmFunction.deleteKey(key, session);
            session.closeSession();
            return true;
        }
        return false;
    }

    public void deleteAllKey() throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = getSession();
            Module pkcs11Module = session.getModule();
            Slot[] slots = pkcs11Module.getSlotList(true);
            for (int i = 0; i < slots.length; i++) {
                Slot slot = slots[i];
                Token token = slot.getToken();
                Object template = new Object();
                session.findObjectsInit(template);
                Object[] arrayOfObject = session.findObjects(100);
                while (arrayOfObject.length > 0) {
                    for (int j = 0; j < arrayOfObject.length; j++) {
                        session.destroyObject(arrayOfObject[j]);
                    }
                    arrayOfObject = session.findObjects(100);
                }
                session.findObjectsFinal();
            }
            System.out.println("All keys were successfully deleted! Hopefully you won't regret it =))");
        }
    }

    public void listAllKey() throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = getSession();
            Module pkcs11Module = session.getModule();
            Slot[] slots = pkcs11Module.getSlotList(true);
            for (int i = 0; i < slots.length; i++) {
                Slot slot = slots[i];
                Token token = slot.getToken();
                Object template = new Object();
                session.findObjectsInit(template);
                Object[] arrayOfObject = session.findObjects(100);
                while (arrayOfObject.length > 0) {
                    for (int j = 0; j < arrayOfObject.length; j++) {
                        Key key = (Key) arrayOfObject[j];
                        System.out.println("=====================================================");
                        System.out.println("Key Info for Slot #" + i + ":\n--------------------------------------------\n" + key);
                        System.out.println("=====================================================\n");
                    }
                    arrayOfObject = session.findObjects(100);
                }
                session.findObjectsFinal();
            }
        }
    }

    public Session getSession() throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        Session session = hsmFunction.openSession(slotNumber);
        return session;
    }

    public void checkAvailableSlot() throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = getSession();
            Module pkcs11Module = session.getModule();
            Slot[] slots = pkcs11Module.getSlotList(true);
            for (int i = 0; i < slots.length; i++) {
                Slot slot = slots[i];
                System.out.println("Slot #" + i);
                System.out.println("Slot ID: " + slot.getSlotID());
                System.out.println(slot.getToken());
                System.out.println("Token Present: " + slot.getSlotInfo().isTokenPresent());
                System.out.println(slot.getModule().getInfo());
                System.out.println("Slot hash code: " + slot.hashCode());
                System.out.println("Slot name: " + slot.getSlotInfo().getSlotDescription() + "\n");
            }
        }
    }

    public List<ECDSAPrivateKey> listECKeys() throws Exception {
        // TODO Auto-generated method stub
        List<ECDSAPrivateKey> keys = new ArrayList<>();
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keys = hsmFunction.listECKeys(session);
            session.closeSession();
        } else {
            throw new Exception("Cannot login to HSM");
        }
        return keys;
    }

    public byte[] sign(long pkcs11MechanismCode, byte[] plaintext, Key privateKey)
            throws PKCS11Exception, TokenException, UnsupportedEncodingException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            if (privateKey == null) {
                session.closeSession();
                return null;
            }
            byte[] signed = hsmFunction.sign(pkcs11MechanismCode, plaintext, privateKey, session);
            session.closeSession();
            return signed;
        }
        return null;
    }

    public boolean idExists(String keyID) throws TokenException {
        boolean isExisted = false;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            isExisted = hsmFunction.idExists(session, keyID);
            session.closeSession();
            return isExisted;
        }
        return isExisted;
    }

    public boolean labelExists(String keyLabel) throws TokenException {
        boolean isExisted = false;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            isExisted = hsmFunction.labelExists(session, keyLabel);
            session.closeSession();
            return isExisted;
        }
        return isExisted;
    }

    public KeyPair genECDSAKeyPair(String keyID, String keyLabel, final ASN1ObjectIdentifier curveId) throws TokenException {
        KeyPair keyPair = null;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keyPair = hsmFunction.genECDSAKeyPair(keyID, keyLabel, curveId, session);
            session.closeSession();
        }
        return keyPair;
    }

    @Override
    public byte[] genCSR(KeyType keyType, String keyLabel, StringBuilder builder) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException {
        if (null == keyType) {
            throw new IllegalArgumentException("Unknown key type: " + keyType);
        }
        switch (keyType) {
            case RSA:
                return genCSR_RSA(keyLabel, builder);
            case ECDSA:
                return genCSR_ECDSA(keyLabel, builder);
        }
        throw new IllegalArgumentException("Unknown key type: " + keyType);
    }

    //GenCSR return Base64
    @Override
    public String gen_CSR(KeyType keyType, String keyLabel, StringBuilder builder) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException {
        if (null == keyType) {
            throw new IllegalArgumentException("Unknown key type: " + keyType);
        } else {
            switch (keyType) {
                case RSA:
                    String base64StringRSA = Base64.getEncoder().encodeToString(genCSR_RSA(keyLabel, builder));
                    String csrRSA = "-----BEGIN CERTIFICATE REQUEST-----" + "\n"
                            + base64StringRSA + "\n" + "-----END CERTIFICATE REQUEST-----";
                    return csrRSA;
                case ECDSA:
                    String base64StringECDSA = Base64.getEncoder().encodeToString(genCSR_ECDSA(keyLabel, builder));
                    String csrECDSA = "-----BEGIN CERTIFICATE REQUEST-----" + "\n"
                            + base64StringECDSA + "\n" + "-----END CERTIFICATE REQUEST-----";
                    return csrECDSA;
            }
        }

        throw new IllegalArgumentException("Unknown key type: " + keyType);
    }

    @Override
    public KeyPair genKeyPair(KeyType keyType, int size, String KeyLabel) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException {
        if (null == keyType) {
            throw new IllegalArgumentException("Unknown key type: " + keyType);
        }
        switch (keyType) {
            case RSA:
                return genRSAKeyPair(size, KeyLabel);
            case ECDSA:
                return genECDSAKeyPair(size, KeyLabel);
        }
        throw new IllegalArgumentException("Unknown key type: " + keyType);
    }

    @Override
    public String genKeyPair(KeyType keyType, int size, StringBuilder builder, String AESKeyName) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException {
        byte[] array = new byte[7];
        (new Random()).nextBytes(array);
        String generatedString = new String(array, Charset.forName("UTF-8"));
        if (null == keyType) {
            throw new IllegalArgumentException("Unknown key type: " + keyType);
        }
        switch (keyType) {
            case RSA:
                return genRSAKeyPair(generatedString, size, builder, AESKeyName);
            case ECDSA:
                return genECDSAKeyPair(size, builder, AESKeyName);
        }
        throw new IllegalArgumentException("Unknown key type: " + keyType);
    }

    @Override
    public synchronized byte[] signHash(byte[] hash, byte[] keyWrapped, String AESKeyName) {
        try {
            return signHashSync(hash, keyWrapped, AESKeyName);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] signHashSync(byte[] hash, byte[] keyWrapped, String AESKeyName) throws TokenException, GeneralSecurityException, UnsupportedEncodingException, IOException, Exception {
        ensureLoggedIn();
        byte[] decodedPrivate = Base64.getDecoder().decode(keyWrapped);
        String jsonString = new String(decodedPrivate, StandardCharsets.UTF_8);
        JsonNode rootNode = parseJson(jsonString);
        String keyType = rootNode.get("KeyAlg").asText();
        String keyName = rootNode.get("KeyName").asText();
        String base64Csr1 = rootNode.get("PrivateKey").asText();
        LOG.debug("Founded Key Type: " + keyType);

        if (aes == null) {
            aes = findAESSecretKey(AESKeyName);
            validateAESSecretKey(aes, AESKeyName);
            PrivateKey privateKey = getPrivateKeyFromCacheOrGenerate(keyName, keyType, base64Csr1, aes);
            return signHashBasedOnKeyType(hash, keyType, privateKey);
        } else {
            validateAESSecretKey(aes, AESKeyName);
            PrivateKey privateKey = getPrivateKeyFromCacheOrGenerate(keyName, keyType, base64Csr1, aes);
            return signHashBasedOnKeyType(hash, keyType, privateKey);
        }
    }

    private void ensureLoggedIn() throws TokenException {
        if (!isLogin()) {
            loginHSM();
        }
    }

    private JsonNode parseJson(String jsonString) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readTree(jsonString);
    }

    private void validateAESSecretKey(AESSecretKey aes, String AESKeyName) throws Exception {
        if (aes == null) {
            throw new Exception("AESSecretKey does not exist: " + AESKeyName);
        }
    }

    private PrivateKey getPrivateKeyFromCacheOrGenerate(String keyName, String keyType, String base64Csr, AESSecretKey aes) throws GeneralSecurityException, IOException, TokenException {
        PrivateKey privateKey = null;
        String cacheKey = keyName + ":" + keyType;
        if (this.keyCache.containsKey(cacheKey)) {
            System.out.println("Key found in cache");
            privateKey = this.keyCache.get(cacheKey);
        }
        if ((keyType.equals("RSA") || keyType.equals("ECDSA")) && privateKey == null) {
            privateKey = findPrivateKey(keyName, keyType);
            if (privateKey == null) {
                generatePrivateKey(keyName, keyType, base64Csr, aes);
            }
            if (privateKey != null) {
                this.keyCache.put(cacheKey, privateKey);
            }
        }
        return privateKey;
    }

    private Key generatePrivateKey(String keyName, String keyType, String base64Csr, AESSecretKey aes) throws GeneralSecurityException, IOException, TokenException {
        byte[] decodedPrivateKeyBytes = Base64.getDecoder().decode(base64Csr);
        return unWrapKey(decodedPrivateKeyBytes, (Key) aes, keyType, keyName);
    }

    private byte[] signHashBasedOnKeyType(byte[] hash, String keyType, PrivateKey privateKey) throws GeneralSecurityException, UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, Exception {
        switch (keyType) {
            case "RSA":
                return signHashRSA(hash, (RSAPrivateKey) privateKey);
            case "ECDSA":
                return signHash(hash, (ECDSAPrivateKey) privateKey);
        }
        throw new IllegalArgumentException("Unknown key type: " + keyType);
    }

    @Override
    public AESSecretKey findAESSecretKey(String keyLabel) throws TokenException {
        if (keyLabel == null || keyLabel.isEmpty()) {
            throw new IllegalArgumentException("Key label must not be null or empty");
        }
        if (!isLogin()) {
            loginHSM();
        }
        Session session = null;
        AESSecretKey foundSecretKey = null;
        try {
            session = this.hsmFunction.openSession(this.slotNumber);
            AESSecretKey secretKeyTemplate = createSecretKeyTemplate(keyLabel);
            session.findObjectsInit((Object) secretKeyTemplate);
            Object[] arrayOfObject = session.findObjects(1);
            if (arrayOfObject.length > 0) {
                foundSecretKey = (AESSecretKey) arrayOfObject[0];
            }
        } finally {
            if (session != null) {
                try {
                    session.findObjectsFinal();
                } finally {
                    session.closeSession();
                }
            }
        }
        return foundSecretKey;
    }

    @Override
    public ECDSAPrivateKey findECDSAPrivateKey(String keyLabel) throws TokenException {

        if (keyLabel == null || keyLabel.isEmpty()) {
            throw new IllegalArgumentException("Key label must not be null or empty");
        }
        if (!isLogin()) {
            loginHSM();
        }
        Session session = null;
        ECDSAPrivateKey foundPrivateKey = null;
        try {
            session = this.hsmFunction.openSession(this.slotNumber);
            ECDSAPrivateKey privateKeyTemplate = new ECDSAPrivateKey();
            privateKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
            privateKeyTemplate.getToken().setBooleanValue(true);
            privateKeyTemplate.getPrivate().setBooleanValue(true);
            privateKeyTemplate.getModifiable().setBooleanValue(true);
            session.findObjectsInit((Object) privateKeyTemplate);
            Object[] arrayOfObject = session.findObjects(1);
            if (arrayOfObject.length > 0) {
                foundPrivateKey = (ECDSAPrivateKey) arrayOfObject[0];
            }
        } finally {
            if (session != null) {
                try {
                    session.findObjectsFinal();
                } finally {
                    session.closeSession();
                }
            }
        }
        return foundPrivateKey;
    }

    private AESSecretKey createSecretKeyTemplate(String keyLabel) {
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
        secretKeyTemplate.getToken().setBooleanValue(true);
        secretKeyTemplate.getPrivate().setBooleanValue(true);
        secretKeyTemplate.getModifiable().setBooleanValue(true);
        return secretKeyTemplate;
    }

    @Override
    public PublicKey findPublicKey(String keyLabel, String keyType) throws TokenException {
        return findPublicKeyTemplate(keyLabel, keyType);
    }

    private PublicKey findPublicKeyTemplate(String keyLabel, String keyType) throws TokenException {
        ECDSAPublicKey eCDSAPublicKey;
        RSAPublicKey rSAPublicKey;
        if (!isLogin()) {
            loginHSM();
        }
        Session session = this.hsmFunction.openSession(this.slotNumber);
        PublicKey foundPublicKey = null;

        if (keyLabel != null) {
            switch (keyType) {
                case "RSA":
                    rSAPublicKey = new RSAPublicKey();
                    rSAPublicKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
                    rSAPublicKey.getToken().setBooleanValue(true);

                    try {
                        session.findObjectsInit((Object) rSAPublicKey);
                        Object[] arrayOfObject = session.findObjects(1);
                        if (arrayOfObject.length > 0) {
                            foundPublicKey = (PublicKey) arrayOfObject[0];
                        }
                    } finally {
                        session.findObjectsFinal();
                        session.closeSession();
                    }
                    break;

                case "ECDSA":
                    eCDSAPublicKey = new ECDSAPublicKey();

                    eCDSAPublicKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
                    eCDSAPublicKey.getToken().setBooleanValue(true);

                    try {
                        session.findObjectsInit((Object) eCDSAPublicKey);
                        Object[] arrayOfObject = session.findObjects(1);
                        if (arrayOfObject.length > 0) {
                            foundPublicKey = (PublicKey) arrayOfObject[0];
                        }
                    } finally {
                        session.findObjectsFinal();
                        session.closeSession();
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported key type");
            }
        } else {
            throw new IllegalArgumentException("Invalid input parameters");
        }

        return foundPublicKey;
    }

    private PrivateKey findPrivateKeyTemplate(String keyLabel, String keyType) throws TokenException {
        RSAPrivateKey rSAPrivateKey;
        ECDSAPrivateKey eCDSAPrivateKey;

        if (!isLogin()) {
            loginHSM();
        }

        Session session = this.hsmFunction.openSession(this.slotNumber);

        PrivateKey foundPrivateKey = null;
        if (keyLabel != null) {
            switch (keyType) {
                case "RSA":
                    rSAPrivateKey = new RSAPrivateKey();

                    rSAPrivateKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
                    rSAPrivateKey.getToken().setBooleanValue(true);
                    rSAPrivateKey.getPrivate().setBooleanValue(true);
                    rSAPrivateKey.getModifiable().setBooleanValue(true);
                    rSAPrivateKey.getSign().setBooleanValue(Boolean.TRUE);
                    rSAPrivateKey.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
                    rSAPrivateKey.getKeyType().setLongValue(PKCS11Constants.CKK_RSA);

                    try {
                        session.findObjectsInit((Object) rSAPrivateKey);
                        Object[] arrayOfObject = session.findObjects(1);
                        if (arrayOfObject.length > 0) {
                            foundPrivateKey = (PrivateKey) arrayOfObject[0];
                        }
                    } finally {
                        session.findObjectsFinal();
                    }
                    break;
                case "ECDSA":
                    eCDSAPrivateKey = new ECDSAPrivateKey();

                    eCDSAPrivateKey.getLabel().setCharArrayValue(keyLabel.toCharArray());
                    eCDSAPrivateKey.getToken().setBooleanValue(true);
                    eCDSAPrivateKey.getPrivate().setBooleanValue(true);
                    eCDSAPrivateKey.getModifiable().setBooleanValue(true);
                    eCDSAPrivateKey.getSign().setBooleanValue(Boolean.TRUE);
                    eCDSAPrivateKey.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
                    eCDSAPrivateKey.getKeyType().setLongValue(PKCS11Constants.CKK_EC);

                    try {
                        session.findObjectsInit((Object) eCDSAPrivateKey);
                        Object[] arrayOfObject = session.findObjects(1);
                        if (arrayOfObject.length > 0) {
                            foundPrivateKey = (PrivateKey) arrayOfObject[0];
                        }
                    } finally {
                        session.findObjectsFinal();
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported key type");
            }
        } else {
            System.out.println("Invalid input parameters - keyType is null");
        }

        session.closeSession();
        return foundPrivateKey;
    }

    @Override
    public PrivateKey findPrivateKey(String keyLabel, String keyType) throws TokenException {
        return findPrivateKeyTemplate(keyLabel, keyType);
    }

    @Override
    public KeyPair genRSAKeyPair(int size, String KeyLabel) throws TokenException {
        KeyPair keyPair = null;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            UUID uuid = UUID.randomUUID();
            String randomString = uuid.toString();
            Session session = this.hsmFunction.openSession(this.slotNumber);
            BigInteger publicExponent = BigInteger.valueOf(65537L);
            if (findPrivateKey(KeyLabel, "RSA") == null && findPublicKey(KeyLabel, "RSA") == null) {
                keyPair = this.hsmFunction.genRSAKeypair(KeyLabel, randomString.getBytes(), session, size, publicExponent);
            } else {
                throw new IllegalArgumentException("Key name alredy exist");
            }
            session.closeSession();
        }
        return keyPair;
    }

    private String genRSAKeyPair(String keyID, int size, StringBuilder builder, String AESKeyName) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException {
        String wrapDataJson;
        if (!isLogin()) {
            loginHSM();
        }
        UUID uuid = UUID.randomUUID();
        String randomString = uuid.toString();
        Session session = this.hsmFunction.openSession(this.slotNumber);
        BigInteger publicExponent = BigInteger.valueOf(65537L);
        KeyPair keyPair = this.hsmFunction.genRSAKeypair(randomString, keyID.getBytes(), session, size, publicExponent);
        Mechanism keyGenerationMechanism = Mechanism.get(8457L);
        AESSecretKey aes = findAESSecretKey(AESKeyName);
        if (aes == null) {
            throw new IllegalArgumentException("AES Key name does not exist");
        }
        byte[] privateKeyBytes = this.hsmFunction.wrapKey((Key) aes, (Key) keyPair.getPrivateKey(), session, keyGenerationMechanism);
        String encodedPrivateKey = Base64.getEncoder().encodeToString(privateKeyBytes);
        byte[] csrBytes = genCSR_RSA(randomString, builder);
        String csr = Base64.getEncoder().encodeToString(csrBytes);
        String encodedPub = Base64.getEncoder().encodeToString(keyPair.getPublicKey().toString().getBytes());
        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> wrapDataMap = new HashMap<>();
        wrapDataMap.put("PrivateKey", encodedPrivateKey);
        wrapDataMap.put("KeyName", randomString);
        wrapDataMap.put("KeyAlg", "RSA");
        try {
            wrapDataJson = mapper.writeValueAsString(wrapDataMap);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
        String encodedWrapDataJson = Base64.getEncoder().encodeToString(wrapDataJson.getBytes("UTF-8"));
        Map<String, String> finalJsonMap = new HashMap<>();
        finalJsonMap.put("csr", csr);
        finalJsonMap.put("Publickey", encodedPub);
        finalJsonMap.put("Wrappeddata", encodedWrapDataJson);
        session.closeSession();
        try {
            return mapper.writeValueAsString(finalJsonMap);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] signHashRSA(byte[] Hash, RSAPrivateKey rsaPrivateKey) throws TokenException, UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, Exception {
        byte[] signature = null;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = this.hsmFunction.openSession(this.slotNumber);
            signature = this.hsmFunction.sign(67L, Hash, (Key) rsaPrivateKey, session);
            session.closeSession();
        }
        return signature;
    }

    private byte[] genCSR_RSA(String keyLabel, StringBuilder builder) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = this.hsmFunction.openSession(this.slotNumber);
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) findPrivateKey(keyLabel, "RSA");
            RSAPublicKey rsaPublicKey = (RSAPublicKey) findPublicKey(keyLabel, "RSA");
            BigInteger modulus = new BigInteger(1, rsaPublicKey.getModulus().getByteArrayValue());
            BigInteger publicExponent = new BigInteger(1, rsaPublicKey.getPublicExponent().getByteArrayValue());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
            byte[] publicKey = keyFactory.generatePublic(keySpec).getEncoded();
            X500Name x500Name = new X500Name(builder.toString());
            byte[] crtReqInf = getCertificateRequestInfo(x500Name, publicKey);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(crtReqInf);
            byte[] hash = md.digest();
            AlgorithmIdentifier hashAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));

            DigestInfo digestInfo = new DigestInfo(hashAlgId, hash);
            byte[] digestInfoBytes = digestInfo.getEncoded();
            byte[] signatureBytes = this.hsmFunction.sign(1L, digestInfoBytes, (Key) rsaPrivateKey, session);
            byte[] csr = createCertificationSignatureRequest(crtReqInf, "SHA256", "RSA", signatureBytes);
            return csr;
        }
        throw new TokenException("HSM login failed.");
    }

    private byte[] genCSR_ECDSA(String keyLabel, StringBuilder builder) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException {
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = this.hsmFunction.openSession(this.slotNumber);

            ECDSAPrivateKey ecPrivateKey = (ECDSAPrivateKey) findPrivateKey(keyLabel, "ECDSA");
            ECDSAPublicKey ecPublicKey = (ECDSAPublicKey) findPublicKey(keyLabel, "ECDSA");

            byte[] encodedAlgorithmIdParameters = ecPublicKey.getEcdsaParams().getByteArrayValue();
            byte[] encodedPoint = DEROctetString.getInstance(ecPublicKey.getEcPoint().getByteArrayValue()).getOctets();

            ECPublicKey ecPublicKey1 = createECPublicKey(encodedAlgorithmIdParameters, encodedPoint);
            
            X500Name x500Name = new X500Name(builder.toString());
            byte[] csrInfo = getCertificateRequestInfo(x500Name, ecPublicKey1.getEncoded());

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(csrInfo);
            byte[] hash = md.digest();

            byte[] sign = this.hsmFunction.signECDSA(PKCS11Constants.CKM_ECDSA, hash, ecPrivateKey, session);
            byte[] r = new byte[sign.length / 2];
            byte[] s = new byte[sign.length / 2];
            System.arraycopy(sign, 0, r, 0, sign.length / 2);
            System.arraycopy(sign, sign.length / 2, s, 0, sign.length / 2);
            BigInteger[] bigSignature = new BigInteger[2];
            bigSignature[0] = new BigInteger(1, r);
            bigSignature[1] = new BigInteger(1, s);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DERSequenceGenerator seq = new DERSequenceGenerator(byteArrayOutputStream);
            seq.addObject((ASN1Encodable) new ASN1Integer(bigSignature[0]));
            seq.addObject((ASN1Encodable) new ASN1Integer(bigSignature[1]));
            seq.close();
            byte[] encodedSignature = byteArrayOutputStream.toByteArray();

            byte[] csr = createCertificationSignatureRequest(csrInfo, "SHA256", "ECDSA", encodedSignature);
            return csr;
        }
        throw new TokenException("HSM login failed.");
    }

    private byte[] getCertificateRequestInfo(X500Name x500Name, byte[] publicKey) throws IOException {
        ASN1Primitive p;
        try (ASN1InputStream input = new ASN1InputStream(publicKey)) {
            p = input.readObject();
        }
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(p);
        CertificationRequestInfo csr = new CertificationRequestInfo(x500Name, pubInfo, null);
        return csr.getEncoded();
    }

    public static byte[] createCertificationSignatureRequest(byte[] certReqInfo, String hash, String keyAlg, byte[] signature) throws IOException, NoSuchAlgorithmException {
        final DerOutputStream der1 = new DerOutputStream();
        der1.write(certReqInfo);
        AlgorithmId.get(hash.concat("with").concat(keyAlg)).encode(der1);
        der1.putBitString(signature);

        final DerOutputStream der2 = new DerOutputStream();
        der2.write((byte) 48, der1);
        return der2.toByteArray();
    }

    // error
    private ECPublicKey create_ECPublicKey(byte[] encodedAlgorithmIdParameters, byte[] encodedPoint) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        try {
            ASN1ObjectIdentifier aSN1ObjectIdentifier = null;
            X962Parameters x962Parameters = null;

            if (encodedAlgorithmIdParameters[0] == 6) {
                aSN1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(encodedAlgorithmIdParameters);
            } else {
                x962Parameters = X962Parameters.getInstance(encodedAlgorithmIdParameters);
            }

            AlgorithmIdentifier algId;
            if (x962Parameters != null) {
                algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, (ASN1Encodable) x962Parameters);
            } else {
                algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey);
            }
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, encodedPoint);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(spki.getEncoded());
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            return (ECPublicKey) kf.generatePublic(keySpec);

        } catch (IOException | NoSuchAlgorithmException | java.security.NoSuchProviderException ex) {
            throw new InvalidKeySpecException("Error creating EC public key", ex);
        }
    }

    private ECPublicKey createECPublicKey(byte[] encodedAlgorithmIdParameters, byte[] encodedPoint) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        try {
            ECNamedCurveParameterSpec parameterSpec = decodeEncodedAlgorithmIdParameters(encodedAlgorithmIdParameters);

            ECCurve curve = parameterSpec.getCurve();
            ECPoint point = curve.decodePoint(encodedPoint);

            ECPublicKeySpec keySpec = new ECPublicKeySpec(point, parameterSpec);
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            System.out.println("createECPublicKey successful..." + "ECPublicKey: " + (ECPublicKey) kf.generatePublic(keySpec));
            return (ECPublicKey) kf.generatePublic(keySpec);
        } catch (IOException | NoSuchAlgorithmException | java.security.NoSuchProviderException ex) {
            throw new InvalidKeySpecException("Error creating EC public key", ex);
        }
    }

    private static ECNamedCurveParameterSpec decodeEncodedAlgorithmIdParameters(byte[] encodedAlgorithmIdParameters) throws IOException {

        if (encodedAlgorithmIdParameters[0] == 6) {
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(encodedAlgorithmIdParameters);
            String curveName = oid.toString();

            return ECNamedCurveTable.getParameterSpec(curveName);
        } else {
            BigInteger oidValue = new BigInteger(1, encodedAlgorithmIdParameters);
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(oidValue.toString());

            X9ECParameters x9Params = X962NamedCurves.getByOID(oid);

            return new ECNamedCurveParameterSpec(
                    oid.getId(),
                    x9Params.getCurve(),
                    x9Params.getG(),
                    x9Params.getN(),
                    x9Params.getH(),
                    x9Params.getSeed()
            );
        }
    }

    @Override
    public KeyPair genECDSAKeyPair(int Lenght, String KeyLabel) throws TokenException {
        KeyPair keyPair = null;
        if (!isLogin()) {
            loginHSM();
        }
        if (isLogin()) {
            Session session = this.hsmFunction.openSession(this.slotNumber);
//            keyPair = this.hsmFunction.genECDSAKeyPair(KeyLabel, Lenght, session);
            if (findPrivateKey(KeyLabel, "ECDSA") == null && findPublicKey(KeyLabel, "ECDSA") == null) {
                keyPair = this.hsmFunction.genECDSAKeyPair(KeyLabel, Lenght, session);
            } else {
                throw new IllegalArgumentException("Key name alredy exist");
            }
            session.closeSession();
        }
        return keyPair;
    }

    public String genECDSAKeyPair(int length, StringBuilder builder, String AESKeyName) throws TokenException, GeneralSecurityException, IOException, OperatorCreationException {
        String wrapDataJson;
        if (!isLogin()) {
            loginHSM();
        }
        if (!isLogin()) {
            return null;
        }
        UUID uuid = UUID.randomUUID();
        String keyLabel = uuid.toString();
        Session session = this.hsmFunction.openSession(this.slotNumber);
        KeyPair keyPair = this.hsmFunction.genECDSAKeyPair(keyLabel, length, session);
        Mechanism keyGenerationMechanism = Mechanism.get(8457L);
        AESSecretKey aes = findAESSecretKey(AESKeyName);
        if (aes == null) {
            throw new IllegalArgumentException("AES Key name does not exist");
        }
        byte[] privateKeyBytes = this.hsmFunction.wrapKey((Key) aes, (Key) keyPair.getPrivateKey(), session, keyGenerationMechanism);
        String encodedPrivateKey = Base64.getEncoder().encodeToString(privateKeyBytes);
        byte[] csrBytes = genCSR_ECDSA(keyPair.getPublicKey().getLabel().toString(), builder);
        String csr = Base64.getEncoder().encodeToString(csrBytes);
        String encodedPub = Base64.getEncoder().encodeToString(keyPair.getPublicKey().toString().getBytes());
        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> wrapDataMap = new HashMap<>();
        wrapDataMap.put("PrivateKey", encodedPrivateKey);
        wrapDataMap.put("KeyName", keyLabel);
        wrapDataMap.put("KeyAlg", "ECDSA");
        try {
            wrapDataJson = mapper.writeValueAsString(wrapDataMap);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
        String encodedWrapDataJson = Base64.getEncoder().encodeToString(wrapDataJson.getBytes("UTF-8"));
        Map<String, String> finalJsonMap = new HashMap<>();
        finalJsonMap.put("csr", csr);
        finalJsonMap.put("publickey", encodedPub);
        finalJsonMap.put("Wrappeddata", encodedWrapDataJson);
        session.closeSession();
        try {
            return mapper.writeValueAsString(finalJsonMap);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public int removeObjects(String keyID, String keyLabel) throws TokenException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
