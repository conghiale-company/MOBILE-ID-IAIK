/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package vn.mobileid.hsm;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.HashSet;

import javax.xml.bind.DatatypeConverter;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.InitializeArgs;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Session.UserType;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11RuntimeException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
//import java.security.Key;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import javax.xml.bind.DatatypeConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;

/**
 *
 * @author Tan_Hung
 */
public class HSMFunction {

    final static Logger logger = LogManager.getLogger(HSMFunction.class);
    private Module module;
    private Slot slotToken = null;

    private boolean isSignInit = false;

    private MechanismInfo signatureMechanismInfo = null;

    public Slot getSlotToken() {
        return slotToken;
    }

    public Token getToken() {
        //return token;
        try {
            return slotToken.getToken();
        } catch (TokenException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null; //
    }

    public void CheckAvailableSlots(String libraryPath, String pkcs11WrapperPath) throws IOException, TokenException {
        Module pkcs11Module = Module.getInstance(libraryPath, pkcs11WrapperPath);
        pkcs11Module.initialize(null);
        Slot[] slots = pkcs11Module.getSlotList(true);
        for (int i = 0; i < slots.length; i++) {
            Slot slot = slots[i];
            System.out.println("Slot #" + i);
            System.out.println("Slot ID: " + slot.getSlotID());
            System.out.println("Slot name: " + slot.getSlotInfo().getSlotDescription() + "\n");
        }
        pkcs11Module.finalize(null);
    }

    public void loadDll(String pkcs11Name, String wrapperName) throws TokenException, IOException {
        if (module != null) {
            return;
        }

//        logger.debug("Load PKCS11 library with params...");
//        logger.debug("PKCS11 lib path: " + pkcs11Name);
//        logger.debug("Wrapper lib path: " + wrapperName);
        
        System.out.println("Load PKCS11 library with params...");
        System.out.println("PKCS11 lib path: " + pkcs11Name);
        System.out.println("Wrapper lib path: " + wrapperName);

        module = Module.getInstance(pkcs11Name, wrapperName);
//        logger.debug("Pre initialize...");
        System.out.println("Pre initialize...");
        long start = System.currentTimeMillis();

        InitializeArgs agrs = new DefaultInitializeArgs();
        module.initialize(agrs);

        System.out.println("Load PKCS11 Library finish, take:" + (System.currentTimeMillis() - start) + " ms");
//        logger.debug("Load PKCS11 Library finish, take: " + (System.currentTimeMillis() - start) + " ms");        
    }

    public AESSecretKey findAESSecretKey(String keyLabel, Session session) throws TokenException {
        if (keyLabel == null) {
            throw new IllegalArgumentException("Invalid input parameters");
        }
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
        secretKeyTemplate.getToken().setBooleanValue(Boolean.valueOf(true));
        secretKeyTemplate.getPrivate().setBooleanValue(Boolean.valueOf(true));
        secretKeyTemplate.getModifiable().setBooleanValue(Boolean.valueOf(true));
        AESSecretKey foundSecretKey = null;
        try {
            session.findObjectsInit((iaik.pkcs.pkcs11.objects.Object) secretKeyTemplate);
            Object[] arrayOfObject = session.findObjects(1);
            if (arrayOfObject.length > 0) {
                foundSecretKey = (AESSecretKey) arrayOfObject[0];
            }
        } finally {
            session.findObjectsFinal();
        }
        return foundSecretKey;
    }

    public void connectToken(int slot) throws TokenException {
        //logger.debug("HSM slot id: {}", slot);
        //logger.debug("module: " + module);		
        Slot[] slots = module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
        if (slots == null || slots.length == 0) {
            throw new TokenException("No token found!");
        }
        //logger.debug("Num of available slot: {}", slots.length);
        for (Slot slot2 : slots) {
            if (slot2.getSlotID() == slot) {
                this.slotToken = slot2;

                HashSet<Mechanism> supportedMechanisms = new HashSet<Mechanism>(Arrays.asList(slot2.getToken().getMechanismList()));

                Token token = slot2.getToken();
                
                if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS))) {
                    signatureMechanismInfo = token.getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS));
                } else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_X_509))) {
                    signatureMechanismInfo = token.getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_X_509));
                } else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_9796))) {
                    signatureMechanismInfo = token.getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_9796));
                } else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_OAEP))) {
                    signatureMechanismInfo = token.getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_OAEP));
                } else {
                    signatureMechanismInfo = null;
                }

                //this.token = slot2.getToken();				
                //logger.debug("HSM slot info: {}", token.getTokenInfo());
                //return token;
                return;
            }
        }
        throw new TokenException("Slot id not found...");
    }

    public Session openSession(int slot) throws TokenException {
        if (slotToken == null) {
            connectToken(slot);
        }

        Token token = slotToken.getToken();

        if (token != null) {
            return token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION, null, null);
        } else {
            throw new TokenException("Token is not present in the slot.");
        }
    }

    public boolean disconnectToken() {
        try {
            logger.debug("Close All session hsm");
            if (slotToken != null) {
                slotToken.getToken().closeAllSessions();
            }

            logger.debug("Unload PKCS#11 library");

            if (module != null) {
                //module.getPKCS11Module().finalize();				
                module.finalize(null);
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean login(Session session, String password) {
        long start = System.currentTimeMillis();
        try {
            session.login(UserType.USER, password.toCharArray());
            logger.debug("Login HSM successful, take: " + (System.currentTimeMillis() - start) + " ms");

            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return false;
    }

    public boolean logout(Session sess) {
        try {
            if (sess != null) {
                sess.logout();
                return true;
            }
        } catch (Exception var1) {
            var1.printStackTrace();

        }
        return false;
    }

    public RSAPublicKey getPublicKeyByID(String KeyID, Session session) throws TokenException {
        RSAPublicKey e = new RSAPublicKey();
        RSAPublicKey temp_key = null;
        e.getId().setByteArrayValue(DatatypeConverter.parseHexBinary(KeyID));

        session.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_rsapublickey = session.findObjects(1);
        session.findObjectsFinal();

        if (temp_rsapublickey != null && temp_rsapublickey.length > 0 && temp_rsapublickey[0] != null) {
            String _keyid = DatatypeConverter.printHexBinary(((RSAPublicKey) temp_rsapublickey[0]).getId().getByteArrayValue());
            if (KeyID.equalsIgnoreCase(_keyid)) {
                temp_key = (RSAPublicKey) temp_rsapublickey[0];
            }
        }

        return temp_key;
    }

    public RSAPrivateKey getPrivateKeyByID(String KeyID, Session session) throws TokenException {
        RSAPrivateKey e = new RSAPrivateKey();
        RSAPrivateKey temp_key = null;
        e.getId().setByteArrayValue(DatatypeConverter.parseHexBinary(KeyID));

        session.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_rsapublickey = session.findObjects(1);
        session.findObjectsFinal();

        if (temp_rsapublickey != null && temp_rsapublickey.length > 0 && temp_rsapublickey[0] != null) {
            String _keyid = DatatypeConverter.printHexBinary(((RSAPrivateKey) temp_rsapublickey[0]).getId().getByteArrayValue());
            if (KeyID.equalsIgnoreCase(_keyid)) {
                temp_key = (RSAPrivateKey) temp_rsapublickey[0];
            }
        }
        return temp_key;
    }

    public AESSecretKey genAESKey(int size, String Keyname, Session session) throws TokenException {
        Mechanism keyGenerationMechanism = Mechanism.get(4224L);
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getValueLen().setLongValue(Long.valueOf((size / 8)));
        secretKeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
        secretKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getLabel().setCharArrayValue(Keyname.toCharArray());
        AESSecretKey secretKey = (AESSecretKey) session.generateKey(keyGenerationMechanism, (Object) secretKeyTemplate);
        return secretKey;
    }

    public AESSecretKey genAESKey(int size, Session session) throws TokenException {
        Mechanism keyGenerationMechanism = Mechanism.get(4224L);
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getValueLen().setLongValue(new Long((size / 8)));
        secretKeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
        secretKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
        AESSecretKey secretKey = (AESSecretKey) session.generateKey(keyGenerationMechanism, (Object) secretKeyTemplate);
        return secretKey;
    }
    
        public KeyPair genRSAKeypair(String keyLabel, byte[] keyID, Session session, int keySize, BigInteger publicExponent) throws TokenException {
        Mechanism keyGenerationMechanism = Mechanism.get(0L);
        BigInteger prime1 = BigInteger.probablePrime(keySize / 2, new SecureRandom());
        BigInteger prime2 = BigInteger.probablePrime(keySize / 2, new SecureRandom());
        RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
        privateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
        privateKeyTemplate.getId().setByteArrayValue(keyID);
        privateKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
        RSAPublicKey publicKeyTemplate = new RSAPublicKey();
        publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
        publicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        publicKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
        publicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        publicKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
        publicKeyTemplate.getId().setByteArrayValue(keyID);
        publicKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
        publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponent.toByteArray());
        publicKeyTemplate.getModulusBits().setLongValue(Long.valueOf(keySize));
        KeyPair keyPair = session.generateKeyPair(keyGenerationMechanism, (Object) publicKeyTemplate, (Object) privateKeyTemplate);
        return keyPair;
    }
    
    public byte[] encrypt(String plainText, RSAPublicKey publicKey, Session session)
            throws TokenException, UnsupportedEncodingException {
        if (plainText == null) {
            return null;
        }
        // be sure that your token can process the specified mechanism

        Mechanism encryptionMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);
        // initialize for encryption
        session.encryptInit(encryptionMechanism, publicKey);
        byte[] rawData = plainText.getBytes("UTF-8");
        byte[] encryptedData = session.encrypt(rawData);
        return encryptedData;
    }

    public byte[] encrypt(byte[] data, RSAPublicKey publicKey, Session session) throws TokenException, UnsupportedEncodingException {
        if (data == null || data.length == 0) {
            return null;
        }
        // be sure that your token can process the specified mechanism
        Mechanism encryptionMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);
        // initialize for encryption
        session.encryptInit(encryptionMechanism, publicKey);
        byte[] encryptedData = session.encrypt(data);
        return encryptedData;
    }
    
    public byte[] decryptData(byte[] cipher, RSAPrivateKey privateKey, Session session) {
        if (cipher == null) {
            return null;
        }
        Mechanism signatureMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);
        try {
            session.decryptInit(signatureMechanism, privateKey);
            byte[] plain1 = session.decrypt(cipher);
            return plain1;
        } catch (TokenException var5) {
            var5.printStackTrace();
            return null;
        }
    }
    
    public ECDSAPrivateKey findECDSAPrivateKey(String keyLabel, Session session) throws TokenException {
        ECDSAPrivateKey privateKeyTemplate = new ECDSAPrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
        privateKeyTemplate.getToken().setBooleanValue(Boolean.valueOf(true));
        privateKeyTemplate.getPrivate().setBooleanValue(Boolean.valueOf(true));
        privateKeyTemplate.getModifiable().setBooleanValue(Boolean.valueOf(true));
        ECDSAPrivateKey foundPrivateKey = null;
        try {
            session.findObjectsInit((Object) privateKeyTemplate);
            Object[] arrayOfObject = session.findObjects(1);
            if (arrayOfObject.length > 0) {
                foundPrivateKey = (ECDSAPrivateKey) arrayOfObject[0];
            }
        } finally {
            session.findObjectsFinal();
        }
        return foundPrivateKey;
    }
    
    public RSAPrivateKey findRSAPrivateKey(String keyLabel, Session session) throws TokenException {
        RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
        privateKeyTemplate.getToken().setBooleanValue(Boolean.valueOf(true));
        privateKeyTemplate.getPrivate().setBooleanValue(Boolean.valueOf(true));
        privateKeyTemplate.getModifiable().setBooleanValue(Boolean.valueOf(true));
        RSAPrivateKey foundPrivateKey = null;
        try {
            session.findObjectsInit((Object) privateKeyTemplate);
            Object[] arrayOfObject = session.findObjects(1);
            if (arrayOfObject.length > 0) {
                foundPrivateKey = (RSAPrivateKey) arrayOfObject[0];
            }
        } finally {
            session.findObjectsFinal();
        }
        return foundPrivateKey;
    }
    
    public void signInit(Mechanism mechanism, Key key, Session session) throws TokenException {
        if (this.isSignInit) {
            System.out.println("Session has already been initialized for signing");
        }
        if (!this.isSignInit) {
            session.signInit(mechanism, (iaik.pkcs.pkcs11.objects.Key) key);
            this.isSignInit = true;
        }
    }
    
    public byte[] sign(long pkcs11MechanismCode, byte[] data, Key privateKey, Session session) throws TokenException {
        if (data == null || data.length == 0) {
            return null;
        }
        Mechanism encryptionMechanism = Mechanism.get(pkcs11MechanismCode);
        RSAPkcsPssParameters rsapssParameters = new RSAPkcsPssParameters(Mechanism.get(592L), 2L, 32L);
        byte[] signed = null;
        encryptionMechanism.setParameters((Parameters) rsapssParameters);
        session.signInit(encryptionMechanism, (iaik.pkcs.pkcs11.objects.Key) privateKey);
        signed = session.sign(data);
        return signed;
    }
    
    public byte[] signECDSA(long pkcs11MechanismCode, byte[] data, Key privateKey, Session session) throws TokenException {
        if (data == null || data.length == 0) {
            return null;
        }
        Mechanism encryptionMechanism = Mechanism.get(pkcs11MechanismCode);
        session.signInit(encryptionMechanism, (iaik.pkcs.pkcs11.objects.Key) privateKey);
        byte[] signed = session.sign(data);
        return signed;
    }
    
    public byte[] sign_ECDSA(long pkcs11MechanismCode, byte[] data, PrivateKey privateKey, Session session) throws TokenException {
        if (data == null || data.length == 0) {
            return null;
        }

        Mechanism mechanism = Mechanism.get(pkcs11MechanismCode);
        session.signInit(mechanism, privateKey);
        return session.sign(data);
    }

    public byte[] sign20210224(long pkcs11MechanismCode, byte[] data, RSAPrivateKey privateKey, Session session) throws TokenException, UnsupportedEncodingException {
        if (data == null || data.length == 0) {
            return null;
        }
        Mechanism encryptionMechanism = Mechanism.get(pkcs11MechanismCode);
        
        session.signInit(encryptionMechanism, privateKey);
        byte[] signed = session.sign(data);
        return signed;
    }
    
    public byte[] wrapKey(Key wrappingKey, Key key, long pkcs11MechanismCode, Session session) throws TokenException {
        if (wrappingKey == null || key == null) {
            return null;
        }
        Mechanism mechanism = Mechanism.get(pkcs11MechanismCode);
        byte[] wrappedKey = session.wrapKey(mechanism, wrappingKey, key);
        return wrappedKey;
    }

    public byte[] wrapKey(Key wrappingKey, Key key, Session session) throws TokenException {
        if ((wrappingKey == null) || (key == null)) {
            return null;
        }

        Mechanism mechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);

        byte[] wrappedKey = session.wrapKey(mechanism, wrappingKey, key);

        return wrappedKey;
    }

    public byte[] wrapKey(Key wrappingKey, Key key, Session session, Mechanism mechanism) throws TokenException {
        if ((wrappingKey == null) || (key == null)) {
            return null;
        }
        byte[] wrappedKey = session.wrapKey(mechanism, wrappingKey, key);
        return wrappedKey;
    }

    public byte[] unwrapAESKey(Key unwrappingKey, byte[] wrappedKey, Session session) throws TokenException {
        if ((wrappedKey == null) || (unwrappingKey == null)) {
            return null;
        }
        Mechanism mechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
        secretKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);

        Key secretKey = session.unwrapKey(mechanism, unwrappingKey, wrappedKey,
                secretKeyTemplate);

        AESSecretKey aes = (AESSecretKey) iaik.pkcs.pkcs11.objects.AESSecretKey.getInstance(session, secretKey.getObjectHandle());
        return aes.getValue().getByteArrayValue();
    }

    public byte[] unwrapAESKey20210224(Key unwrappingKey, byte[] wrappedKey, Session session) throws TokenException {
        if ((wrappedKey == null) || (unwrappingKey == null)) {
            return null;
        }
        Mechanism mechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
        secretKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);

        AESSecretKey secretKey = (AESSecretKey) session.unwrapKey(mechanism, unwrappingKey, wrappedKey,
                secretKeyTemplate);
        return secretKey.getValue().getByteArrayValue();
    }
    
    public String importKey(String keyId, byte[] prExp, byte[] modulus, Session session) throws TokenException {

        RSAPrivateKey temp_key = new RSAPrivateKey();
        temp_key.getId().setByteArrayValue(DatatypeConverter.parseHexBinary(keyId));
        // set private exponent
        temp_key.getPrivateExponent().setByteArrayValue(prExp);
        // set modulus
        temp_key.getModulus().setByteArrayValue(modulus);
        // set attribute never Extractable
        temp_key.getNeverExtractable().setBooleanValue(Boolean.FALSE);
        // set attribute sensitive
        temp_key.getAlwaysSensitive().setBooleanValue(Boolean.FALSE);
        // set decrypt
        temp_key.getDecrypt().setBooleanValue(Boolean.TRUE);
        temp_key.getSign().setBooleanValue(Boolean.TRUE);
        temp_key.getToken().setBooleanValue(Boolean.TRUE);
        temp_key.getExtractable().setBooleanValue(Boolean.TRUE);
        temp_key.getSensitive().setBooleanValue(Boolean.FALSE);

        //temp_key.getPublicExponent().setByteArrayValue(new byte[]{0x01,0x00,0x01});
        iaik.pkcs.pkcs11.objects.Object object = session.createObject(temp_key);
        return ((Key) object).getId().toString();
    }
    
    public String importKey(String keyId, ECDSAPrivateKey privateKey, Session session) throws TokenException {
        ECDSAPrivateKey pkcs11EcPrivateKey = new ECDSAPrivateKey();
        pkcs11EcPrivateKey.getSensitive().setBooleanValue(Boolean.TRUE);
        pkcs11EcPrivateKey.getExtractable().setBooleanValue(Boolean.TRUE);
        pkcs11EcPrivateKey.getToken().setBooleanValue(Boolean.TRUE);
        pkcs11EcPrivateKey.getPrivate().setBooleanValue(Boolean.TRUE);
        pkcs11EcPrivateKey.getId().setByteArrayValue(DatatypeConverter.parseHexBinary(keyId.replace("-", "")));
        pkcs11EcPrivateKey.getSign().setBooleanValue(Boolean.TRUE);
        pkcs11EcPrivateKey.getDecrypt().setBooleanValue(Boolean.TRUE);
        pkcs11EcPrivateKey.getDerive().setBooleanValue(Boolean.TRUE);
        pkcs11EcPrivateKey.getUnwrap().setBooleanValue(Boolean.TRUE);
        pkcs11EcPrivateKey.getEcdsaParams().setByteArrayValue(privateKey.getEcdsaParams().getByteArrayValue());
        pkcs11EcPrivateKey.getValue().setByteArrayValue(privateKey.getValue().getByteArrayValue());
        Object object = session.createObject((Object) pkcs11EcPrivateKey);
        return ((Key) object).getId().toString();
    }
    
    public String importKey(String keyLabel, Key key, Session session) throws TokenException {
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getValue().setByteArrayValue(((java.security.Key) key).getEncoded());
        secretKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
        secretKeyTemplate.getToken().setBooleanValue(Boolean.valueOf(true));
        secretKeyTemplate.getPrivate().setBooleanValue(Boolean.valueOf(true));
        secretKeyTemplate.getModifiable().setBooleanValue(Boolean.valueOf(true));
        Object object = session.createObject((Object) secretKeyTemplate);
        return ((Key) object).getId().toString();
    }
    
    //RSA
    public String importKey(String keyId, java.security.interfaces.RSAPrivateKey privateKey, Session session) throws TokenException {
        RSAPrivateKey pkcs11RsaPrivateKey = new RSAPrivateKey();

        pkcs11RsaPrivateKey.getSensitive().setBooleanValue(Boolean.TRUE);
        //pkcs11RsaPrivateKey.getExtractable().setBooleanValue(Boolean.FALSE);
        pkcs11RsaPrivateKey.getToken().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getPrivate().setBooleanValue(Boolean.TRUE);

        pkcs11RsaPrivateKey.getId().setByteArrayValue(DatatypeConverter.parseHexBinary(keyId.replace("-", "")));

        pkcs11RsaPrivateKey.getSign().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getSignRecover().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getDecrypt().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getDerive().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getUnwrap().setBooleanValue(Boolean.TRUE);

        pkcs11RsaPrivateKey.getModulus().setByteArrayValue(
                iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(privateKey.getModulus()));
        pkcs11RsaPrivateKey.getPrivateExponent().setByteArrayValue(
                iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(privateKey.getPrivateExponent()));

        iaik.pkcs.pkcs11.objects.Object object = session.createObject(pkcs11RsaPrivateKey);

        return ((Key) object).getId().toString();
    }
    
    public Key unwrapKey(Key unwrappingKey, byte[] wrappedKey, Session session, Mechanism mechanism, Long keyType, String keyID, boolean isToken) throws TokenException {
        if ((wrappedKey == null) || (unwrappingKey == null)) {
            return null;
        }
        RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();
        rsaPrivateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        rsaPrivateKeyTemplate.getId().setByteArrayValue(keyID.getBytes());
        rsaPrivateKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());
        rsaPrivateKeyTemplate.getKeyType().setLongValue(PKCS11Constants.CKK_RSA);

        rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);

        rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getDerive().setBooleanValue(Boolean.FALSE);

        return session.unwrapKey(mechanism, unwrappingKey, wrappedKey, rsaPrivateKeyTemplate);
    }
    
    public Key unwrapRSAKey(Key unwrappingKey, byte[] wrappedKey, Session session, Mechanism mechanism, Long keyType, String keyID, boolean isToken) throws TokenException {
        if (wrappedKey == null || unwrappingKey == null) {
            return null;
        }
        RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();
        rsaPrivateKeyTemplate.getObjectClass().setLongValue(Long.valueOf(3L));
        rsaPrivateKeyTemplate.getId().setByteArrayValue(keyID.getBytes());
        rsaPrivateKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());
        rsaPrivateKeyTemplate.getKeyType().setLongValue(Long.valueOf(0L));
        rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getDerive().setBooleanValue(Boolean.FALSE);
        return session.unwrapKey(mechanism, unwrappingKey, wrappedKey, (Object) rsaPrivateKeyTemplate);
    }
    
    public Key unwrapECDSAKey(Key unwrappingKey, byte[] wrappedKey, String label, Long keyType, String keyID, Mechanism mechanism, Session session) throws TokenException {
        if ((wrappedKey == null) || (unwrappingKey == null)) {
            return null;
        }

        ECDSAPrivateKey ecdsaPrivateKeyTemplate = new ECDSAPrivateKey();

        byte[] idBytes = DatatypeConverter.parseHexBinary(keyID.replace("-", ""));
        ecdsaPrivateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        ecdsaPrivateKeyTemplate.getId().setByteArrayValue(idBytes);
        ecdsaPrivateKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());
        ecdsaPrivateKeyTemplate.getKeyType().setLongValue(PKCS11Constants.CKK_ECDSA);
        
        ecdsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
        ecdsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);

        ecdsaPrivateKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getDerive().setBooleanValue(Boolean.FALSE);

        return session.unwrapKey(mechanism, unwrappingKey, wrappedKey, ecdsaPrivateKeyTemplate);
    }
    
    public Key unwrapECDSAKey(Key unwrappingKey, byte[] wrappedKey, Session session, Mechanism mechanism, Long keyType, String keyID, boolean isToken) throws TokenException {
        if ((wrappedKey == null) || (unwrappingKey == null)) {
            return null;
        }

        ECDSAPrivateKey ecdsaPrivateKeyTemplate = new ECDSAPrivateKey();

        byte[] idBytes = DatatypeConverter.parseHexBinary(keyID.replace("-", ""));
        ecdsaPrivateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        ecdsaPrivateKeyTemplate.getId().setByteArrayValue(idBytes);
        ecdsaPrivateKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());
        ecdsaPrivateKeyTemplate.getKeyType().setLongValue(PKCS11Constants.CKK_ECDSA);

        ecdsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
        ecdsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);

        ecdsaPrivateKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getDerive().setBooleanValue(Boolean.FALSE);

        return session.unwrapKey(mechanism, unwrappingKey, wrappedKey, ecdsaPrivateKeyTemplate);
    }
    
    public AESSecretKey genAESKey(String keyID, int size, Session session, boolean isToken, boolean isSensitive) throws TokenException {

        Mechanism keyGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getValueLen().setLongValue(new Long(size / 8));
        secretKeyTemplate.getSensitive().setBooleanValue(isSensitive);
        secretKeyTemplate.getToken().setBooleanValue(isToken);              // not  store in hsm
        secretKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);

        secretKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE); // acb
        secretKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE); // acb

        secretKeyTemplate.getModifiable().setBooleanValue(Boolean.FALSE);
        secretKeyTemplate.getId().setByteArrayValue(keyID.getBytes());
        secretKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());

        secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getKeyType().setLongValue(PKCS11Constants.CKK_AES);
        secretKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_SECRET_KEY);

        AESSecretKey secretKey = (AESSecretKey) session.generateKey(keyGenerationMechanism, secretKeyTemplate);
        return secretKey;
    }

    public void deleteKey(Key key, Session session) throws TokenException {
        session.destroyObject(key);
    }

    public Key getKeyByID(String KeyID, Session session) throws TokenException {
        Key e = new Key();
        e.getId().setByteArrayValue(KeyID.getBytes());
        session.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_rsapublickey = session.findObjects(10);
        session.findObjectsFinal();

        for (iaik.pkcs.pkcs11.objects.Object iaikObj : temp_rsapublickey) {
            if (iaikObj instanceof Key) {
                return (Key) iaikObj;
            }
        }
        return null;
    }
    
    public List<ECDSAPrivateKey> getECKeyByID(Session session, String keyID) throws TokenException {
        List<ECDSAPrivateKey> keys = new ArrayList<>();

        ECDSAPrivateKey e = new ECDSAPrivateKey();
        e.getId().setByteArrayValue(keyID.getBytes());

        session.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_eccPrivKey = session.findObjects(10);
        session.findObjectsFinal();

        if (temp_eccPrivKey != null) {
            for (int i = 0; i < temp_eccPrivKey.length; i++) {
                keys.add((ECDSAPrivateKey) temp_eccPrivKey[i]);
            }
        }
        return keys;
    }
    
    public List<ECDSAPrivateKey> getECKeyByLabel(Session session, String keyLabel) throws TokenException {
        List<ECDSAPrivateKey> keys = new ArrayList<>();

        ECDSAPrivateKey e = new ECDSAPrivateKey();
        e.getLabel().setCharArrayValue(keyLabel.toCharArray());

        session.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_eccPrivKey = session.findObjects(10);
        session.findObjectsFinal();

        if (temp_eccPrivKey != null) {
            for (int i = 0; i < temp_eccPrivKey.length; i++) {
                keys.add((ECDSAPrivateKey) temp_eccPrivKey[i]);
            }
        }
        return keys;
    }
    
    public List<ECDSAPublicKey> getPublicECKeyByID(Session session, String keyID) throws TokenException {
        List<ECDSAPublicKey> keys = new ArrayList<>();

        ECDSAPublicKey e = new ECDSAPublicKey();
        e.getId().setByteArrayValue(keyID.getBytes());

        session.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_eccPrivKey = session.findObjects(10);
        session.findObjectsFinal();

        if (temp_eccPrivKey != null) {
            for (int i = 0; i < temp_eccPrivKey.length; i++) {
                keys.add((ECDSAPublicKey) temp_eccPrivKey[i]);
            }
        }
        return keys;
    }
    
    public List<ECDSAPublicKey> getPublicECKeyByLabel(Session session, String keyLabel) throws TokenException {
        List<ECDSAPublicKey> keys = new ArrayList<>();

        ECDSAPublicKey e = new ECDSAPublicKey();
        e.getLabel().setCharArrayValue(keyLabel.toCharArray());

        session.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_eccPrivKey = session.findObjects(10);
        session.findObjectsFinal();

        if (temp_eccPrivKey != null) {
            for (int i = 0; i < temp_eccPrivKey.length; i++) {
                keys.add((ECDSAPublicKey) temp_eccPrivKey[i]);
            }
        }
        return keys;
    }
    
    public List<ECDSAPrivateKey> listECKeys(Session session) throws TokenException {
        List<ECDSAPrivateKey> keys = new ArrayList<>();
        ECDSAPrivateKey e = new ECDSAPrivateKey();
        session.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_eccPrivKey = session.findObjects(10);
        session.findObjectsFinal();
        if (temp_eccPrivKey != null) {
            for (int i = 0; i < temp_eccPrivKey.length; i++) {
                keys.add((ECDSAPrivateKey) temp_eccPrivKey[i]);
            }
        }
        return keys;
    }
    
    public KeyPair genECDSAKeyPair(String keyID, String keyLabel, final ASN1ObjectIdentifier curveId, Session session) throws TokenException {

        Mechanism keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_ECDSA_KEY_PAIR_GEN);

        ECDSAPublicKey ecdsaPublicKeyTemplate = new ECDSAPublicKey();
        ecdsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        ecdsaPublicKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
        ecdsaPublicKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
        ecdsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
        

        ECDSAPrivateKey ecdsaPrivateKeyTemplate = new ECDSAPrivateKey();
        ecdsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getSensitive().getBooleanValue();
        ecdsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);

        setKeyAttributes(keyID, keyLabel, PKCS11Constants.CKK_ECDSA, ecdsaPublicKeyTemplate, ecdsaPrivateKeyTemplate);

        byte[] encodedCurveId;
        try {
            encodedCurveId = curveId.getEncoded();
        } catch (IOException ex) {
            throw new TokenException(ex.getMessage(), ex);
        }
        try {
            ecdsaPublicKeyTemplate.getEcdsaParams().setByteArrayValue(encodedCurveId);
            return session.generateKeyPair(keyPairGenerationMechanism, ecdsaPublicKeyTemplate, ecdsaPrivateKeyTemplate);
        } catch (TokenException ex) {
            X9ECParameters ecParams = ECNamedCurveTable.getByOID(curveId);
            if (ecParams == null) {
                throw new IllegalArgumentException("could not get X9ECParameters for curve "
                        + curveId.getId());
            }

            try {
                ecdsaPublicKeyTemplate.getEcdsaParams().setByteArrayValue(ecParams.getEncoded());
            } catch (IOException ex2) {
                throw new TokenException(ex.getMessage(), ex);
            }
            return session.generateKeyPair(keyPairGenerationMechanism, ecdsaPublicKeyTemplate, ecdsaPrivateKeyTemplate);
        }
    }
    
    public KeyPair genECDSAKeyPair(String keyLabel, int Length, Session session) throws TokenException {
        ASN1ObjectIdentifier curveId;
        byte[] encodedCurveId;
        switch (Length) {
            case 384:
                curveId = new ASN1ObjectIdentifier("1.3.132.0.34");
                break;
            case 512:
                curveId = new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.13");
                break;
            case 521:
                curveId = new ASN1ObjectIdentifier("1.3.132.0.35");
                break;
            default:
                curveId = new ASN1ObjectIdentifier("1.2.840.10045.3.1.7");
                break;
        }
        Mechanism keyPairGenerationMechanism = Mechanism.get(4160L);
        ECDSAPublicKey ecdsaPublicKeyTemplate = new ECDSAPublicKey();
        ECDSAPrivateKey ecdsaPrivateKeyTemplate = new ECDSAPrivateKey();
        ecdsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getSensitive().getBooleanValue();
        ecdsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        ecdsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
//        byte[] array = new byte[7];
//        (new Random()).nextBytes(array);
//        String generatedString = new String(array, Charset.forName("UTF-8"));
        String keyId = keyLabel;
        setKeyAttributes(keyId, keyLabel, 3L, (PublicKey) ecdsaPublicKeyTemplate, (PrivateKey) ecdsaPrivateKeyTemplate);
        try {
            encodedCurveId = curveId.getEncoded();
        } catch (IOException ex) {
            throw new TokenException(ex.getMessage(), ex);
        }
        try {
            ecdsaPublicKeyTemplate.getEcdsaParams().setByteArrayValue(encodedCurveId);
            return session.generateKeyPair(keyPairGenerationMechanism, (Object) ecdsaPublicKeyTemplate, (Object) ecdsaPrivateKeyTemplate);
        } catch (TokenException ex) {
            X9ECParameters ecParams = ECNamedCurveTable.getByOID(curveId);
            if (ecParams == null) {
                throw new IllegalArgumentException("Could not get X9ECParameters for curve " + curveId
                        .getId());
            }
            try {
                ecdsaPublicKeyTemplate.getEcdsaParams().setByteArrayValue(ecParams.getEncoded());
            } catch (IOException ex2) {
                throw new TokenException(ex.getMessage(), ex);
            }
            return session.generateKeyPair(keyPairGenerationMechanism, (Object) ecdsaPublicKeyTemplate, (Object) ecdsaPrivateKeyTemplate);
        }
    }
    
    public boolean idExists(final Session session, final String keyId) throws TokenException {
        Key key = new Key();
        key.getId().setByteArrayValue(keyId.getBytes());

        Object[] objects;
        try {
            session.findObjectsInit(key);
            objects = session.findObjects(10);
            session.findObjectsFinal();
            if (objects.length > 0) {
                return true;
            }

            X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
            cert.getId().setByteArrayValue(keyId.getBytes());

            session.findObjectsInit(cert);
            objects = session.findObjects(10);
            session.findObjectsFinal();
        } catch (TokenException ex) {
            throw new TokenException(ex.getMessage(), ex);
        }

        return objects.length > 0;
    }
    
    public boolean labelExists(final Session session,
            final String keyLabel) throws TokenException {

        Key key = new Key();
        key.getLabel().setCharArrayValue(keyLabel.toCharArray());

        Object[] objects;
        try {
            session.findObjectsInit(key);
            objects = session.findObjects(1);
            session.findObjectsFinal();
            if (objects.length > 0) {
                return true;
            }

            X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
            cert.getLabel().setCharArrayValue(keyLabel.toCharArray());

            session.findObjectsInit(cert);
            objects = session.findObjects(1);
            session.findObjectsFinal();
        } catch (TokenException ex) {
            throw new TokenException(ex.getMessage(), ex);
        }

        return objects.length > 0;
    }
    
    private void setKeyAttributes(final String id, final String label, final long keyType,
            final PublicKey publicKey, final PrivateKey privateKey) {
        if (privateKey != null) {
            privateKey.getToken().setBooleanValue(true);
            privateKey.getId().setByteArrayValue(id.getBytes());
            privateKey.getLabel().setCharArrayValue(label.toCharArray());
            privateKey.getKeyType().setLongValue(keyType);
            privateKey.getSign().setBooleanValue(true);
            privateKey.getPrivate().setBooleanValue(true);
            privateKey.getSensitive().setBooleanValue(true);

            privateKey.getExtractable().setBooleanValue(true);
//            privateKey.getWrapWithTrusted().setBooleanValue(true);
            privateKey.getUnwrap().setBooleanValue(true);
            privateKey.getDerive().setBooleanValue(true);
//            privateKey.getAlwaysAuthenticate().setBooleanValue(true);
        }

        if (publicKey != null) {
            publicKey.getToken().setBooleanValue(true);
            publicKey.getId().setByteArrayValue(id.getBytes());
            publicKey.getLabel().setCharArrayValue(label.toCharArray());
            publicKey.getKeyType().setLongValue(keyType);
            publicKey.getVerify().setBooleanValue(true);
            publicKey.getModifiable().setBooleanValue(Boolean.TRUE);
        }
    }
    
    public KeyPair genRSAKeyPair(String keyID, int size, BigInteger publicExponent, Session session) throws TokenException {

        byte[] id = keyID.getBytes(); //DatatypeConverter.parseHexBinary(keyID);

        Mechanism keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN); //CKM_RSA_PKCS_KEY_PAIR_GEN
        RSAPublicKey rsaPublicKeyTemplate = new RSAPublicKey();
        RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();

        // set the general attributes for the public key
        rsaPublicKeyTemplate.getModulusBits().setLongValue(new Long(size));
        byte[] publicExponentBytes = {0x01, 0x00, 0x01}; // 2^16 + 1
        if (publicExponent != null) {
            publicExponentBytes = bigToByteArray(publicExponent);
        }
        rsaPublicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
        rsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        rsaPublicKeyTemplate.getId().setByteArrayValue(id);
        rsaPublicKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());
        //add for trident
        rsaPublicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        rsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
        rsaPublicKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);

        rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE); //-> allow wrap
        rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);

        rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getDerive().setBooleanValue(Boolean.FALSE);

        rsaPrivateKeyTemplate.getId().setByteArrayValue(id);
        rsaPrivateKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());

        rsaPublicKeyTemplate.getKeyType().setPresent(false);
        rsaPublicKeyTemplate.getObjectClass().setPresent(false);

        rsaPrivateKeyTemplate.getKeyType().setPresent(false);
        rsaPrivateKeyTemplate.getObjectClass().setPresent(false);
        return session.generateKeyPair(keyPairGenerationMechanism, rsaPublicKeyTemplate, rsaPrivateKeyTemplate);
    }
    
    private byte[] bigToByteArray(BigInteger x) {
        String hex = x.toString(16);
        if (hex.length() % 2 != 0) {
            hex = '0' + hex;
        }
        return DatatypeConverter.parseHexBinary(hex);
    }
    
//    Not Use
    public String signJWTByEDCSA(String header, String payload, PrivateKey privateKey, Session session) throws Exception {
        String dataToBeSign = base64UrlEncode(header) + "." + base64UrlEncode(payload);
        byte[] hashedBytes = hashDataWithSha256(dataToBeSign.getBytes("UTF-8"));

        String jwt;
//        Sign the payload
        Mechanism signatureMechanism = Mechanism.get(PKCS11Constants.CKM_ECDSA_SHA256);
        try {
            session.signInit(signatureMechanism, privateKey);
            byte[] signature = session.sign(hashedBytes);

//            Encode the signature to Base64
            String encodedSignature = base64UrlEncode(signature);

            if (!encodedSignature.isEmpty())
                System.out.println("JWT signature created successfully");
            else
                System.out.println("JWT signature could not be created");

//            Output the JWT
            jwt = dataToBeSign + "." + encodedSignature;
        } catch (TokenException e) {
            throw new GeneralSecurityException(e);
        }

        return jwt;
    }

//    Encode the signature as Base64 URL-safe string
    public String base64UrlEncode(String input) {
        return Base64.getUrlEncoder().encodeToString(input.getBytes())
                .replaceAll("=", "");
    }

//    Encode the signature as Base64 URL-safe string
    public String base64UrlEncode(byte[] input) {
        return Base64.getUrlEncoder().encodeToString(input)
                .replaceAll("=", "");
    }

//    Method to compute SHA-256 hash
    public byte[] hashDataWithSha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

//    Verify signature jwt by EDCSA
    public boolean verifySignature(Session session, PublicKey publicKey, String header, String payload, byte[] signature) throws Exception {
        String dataToBeSign = header + "." + payload;
        byte[] hashedBytes = hashDataWithSha256(dataToBeSign.getBytes("UTF-8"));

        Mechanism signatureMechanism = Mechanism.get(4161L);
        try {
            session.verifyInit(signatureMechanism, publicKey);
            session.verify(hashedBytes, signature);
            System.out.println("SIGNATURE JWT VALID!!!");
            return true;
        } catch (PKCS11RuntimeException e) {
            System.out.println("SIGNATURE JWT INVALID!!!" + e);
            return false;
        }
    }
}
