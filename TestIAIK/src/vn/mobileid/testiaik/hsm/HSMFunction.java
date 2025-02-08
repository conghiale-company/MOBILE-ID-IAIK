package vn.mobileid.testiaik.hsm;

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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;

public class HSMFunction {

    final static Logger logger = LogManager.getLogger(HSMFunction.class);
    private Module module;
    private Slot slotToken = null;

    //private HashSet<Mechanism> supportedMechanisms = null;
    private MechanismInfo signatureMechanismInfo = null;
    //private Token token = null;

    //private ReentrantLock lock = new ReentrantLock();
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

        return null;
    }

    public void loadDll(String pkcs11Name, String wrapperName) throws TokenException, IOException {
        if (module != null) {
            return;
        }

        logger.debug("Load PKCS11 library with params...");
        logger.debug("PKCS11 lib path: " + pkcs11Name);
        logger.debug("Wrapper lib path: " + wrapperName);

        module = Module.getInstance(pkcs11Name, wrapperName);
        logger.debug("Pre initialize...");
        long start = System.currentTimeMillis();

        /*try{
         //logger.debug("Info " + module.getInfo());
         if(module.getPKCS11Module().C_GetInfo().flags == PKCS11Constants.CKR_OK)
         module.finalize(null);
         }catch (Exception e) {
         // TODO: handle exception
         }*/
        InitializeArgs agrs = new DefaultInitializeArgs();
        module.initialize(agrs);

        logger.debug("Load PKCS11 Library finish, take: " + (System.currentTimeMillis() - start) + " ms");

        /*String hsmLibPath = "/usr/lib/libcs_pkcs11_R2.so";
         String wrapperLibPath = "/home/mobileid/hsm/libpkcs11wrapper.so";		
         logger.debug("HSM lib path: {}", hsmLibPath);
         logger.debug("Wrapper lib path: {}", wrapperLibPath);		
         try {
         module = Module.getInstance(hsmLibPath,
         wrapperLibPath);
         module.initialize(null);
         } catch (IOException | TokenException e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
         }	*/
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
            logger.debug("HSM slot id: " + slot2.getSlotID() + ".\n Info: " + slot2.toString());
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
        //SlotInfo slotInfo = null;

        /*if(slotToken != null){
         lock.lock();
         SlotInfo slotInfo = null;
         try{
         slotInfo = slotToken.getSlotInfo();
         }catch (Exception e) {
         // TODO: handle exception
         }finally {
         lock.unlock();
         }
         logger.debug("SlotInfo: " + slotInfo);
         if(slotInfo == null || !slotInfo.isTokenPresent())			
         throw new TokenException("Token has been removed");
			
         }else if(slotToken == null){
         connectToken(slot);			
         }*/
        if (slotToken == null) {
            connectToken(slot);
        }
        long start = System.currentTimeMillis();
        Session sss = slotToken.getToken().openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION, null, null);
        return sss;

    }

    /*public synchronized Session openSession(int slot) throws TokenException{
     try{
     if(token == null)
     token = connectToken(slot);
			
     if(token != null){
     return token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION, null, null);
     }else
     return null;
     }catch (Exception e) {
     // TODO: handle exception
     e.printStackTrace();
     token = connectToken(slot);
     if(token != null){
     return token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION, null, null);
     }else
     return null;
			
     return null;
     }
     }*/
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
            // TODO Auto-generated catch block
            e.printStackTrace();

        }
        return false;
    }

    public boolean login(Session session, String password, boolean asUser) {
        long start = System.currentTimeMillis();
        try {
            session.login(asUser, password.toCharArray());//UserType.USER
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

        /*if (temp_rsapublickey.length > 0) {
         for (int i = 0; i < temp_rsapublickey.length; ++i) {
         temp_key = (RSAPrivateKey) temp_rsapublickey[i];
         String _keyid = DatatypeConverter.printHexBinary(temp_key.getId().getByteArrayValue());
         if (KeyID.compareTo(_keyid) == 0) {
         break;
         }
         }
         }*/
        return temp_key;
    }

    public AESSecretKey genAESKey(int size, Session session) throws TokenException {
        Mechanism keyGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);

        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getValueLen().setLongValue(new Long(size / 8));
        secretKeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
        secretKeyTemplate.getToken().setBooleanValue(Boolean.FALSE); // not
        secretKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
        

        AESSecretKey secretKey = (AESSecretKey) session.generateKey(keyGenerationMechanism, secretKeyTemplate);
        // return secretKey.getValue().getByteArrayValue();
        return secretKey;
    }

    public AESSecretKey genAESKey(byte[] value, Session session) throws TokenException {
        Mechanism keyGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);

        AESSecretKey secretKeyTemplate = new AESSecretKey();
        secretKeyTemplate.getValueLen().setLongValue(new Long(value.length));

        secretKeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
        secretKeyTemplate.getToken().setBooleanValue(Boolean.FALSE); // not
        // store
        // in
        // hsm
        secretKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getValue().setByteArrayValue(value);

        AESSecretKey secretKey = (AESSecretKey) session.generateKey(keyGenerationMechanism, secretKeyTemplate);
        return secretKey;
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

    public byte[] sign(long pkcs11MechanismCode, byte[] data, Key privateKey, Session session) throws TokenException, UnsupportedEncodingException {
        if (data == null || data.length == 0) {
            return null;
        }
        // be sure that your token can process the specified mechanism
        Mechanism encryptionMechanism = Mechanism.get(pkcs11MechanismCode);
        //encryptionMechanism.setParameters(PKCS11Constants.CKM_MD5_RSA_PKCS);
        // initialize for encryption
        session.signInit(encryptionMechanism, privateKey);
        byte[] signed = session.sign(data);
        return signed;
    }

    public byte[] sign20210224(long pkcs11MechanismCode, byte[] data, RSAPrivateKey privateKey, Session session) throws TokenException, UnsupportedEncodingException {
        if (data == null || data.length == 0) {
            return null;
        }
        // be sure that your token can process the specified mechanism
        Mechanism encryptionMechanism = Mechanism.get(pkcs11MechanismCode);
        //encryptionMechanism.setParameters(PKCS11Constants.CKM_MD5_RSA_PKCS);
        // initialize for encryption
        session.signInit(encryptionMechanism, privateKey);
        byte[] signed = session.sign(data);
        return signed;
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

    public String importKey(String keyId, java.security.interfaces.RSAPrivateKey privateKey, Session session) throws TokenException {
        // TODO Auto-generated method stub
        // create private key object template
        RSAPrivateKey pkcs11RsaPrivateKey = new RSAPrivateKey();

        pkcs11RsaPrivateKey.getSensitive().setBooleanValue(Boolean.TRUE);
        //pkcs11RsaPrivateKey.getExtractable().setBooleanValue(Boolean.FALSE);
        pkcs11RsaPrivateKey.getToken().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getPrivate().setBooleanValue(Boolean.TRUE);
        //String keyLabel = userCommonName + "'s " + ((Name) userCertificate.getIssuerDN()).getRDN(ObjectID.organization);
        //pkcs11RsaPrivateKey.getLabel().setCharArrayValue(keyLabel.toCharArray());

        pkcs11RsaPrivateKey.getId().setByteArrayValue(DatatypeConverter.parseHexBinary(keyId.replace("-", "")));

        //pkcs11RsaPrivateKey.getSubject().setByteArrayValue(((Name) userCertificate.getSubjectDN()).getEncoded());
        pkcs11RsaPrivateKey.getSign().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getSignRecover().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getDecrypt().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getDerive().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getUnwrap().setBooleanValue(Boolean.TRUE);

        pkcs11RsaPrivateKey.getModulus().setByteArrayValue(
                iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(privateKey.getModulus()));
        pkcs11RsaPrivateKey.getPrivateExponent().setByteArrayValue(
                iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(privateKey.getPrivateExponent()));
        /*pkcs11RsaPrivateKey.getPublicExponent().setByteArrayValue(
         iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(
         ((java.security.interfaces.RSAPublicKey) userCertificate.getPublicKey()).getPublicExponent()));*/

        //logger.debug("Templete  key \n{}", pkcs11RsaPrivateKey);
        iaik.pkcs.pkcs11.objects.Object object = session.createObject(pkcs11RsaPrivateKey);

        //logger.info("Object created: {}", object);
        return ((Key) object).getId().toString();
    }

    public Key unwrapKey(Key unwrappingKey, byte[] wrappedKey, Session session, Mechanism mechanism, Long keyType, String keyID, boolean isToken) throws TokenException {
        if ((wrappedKey == null) || (unwrappingKey == null)) {
            return null;
        }
        /*
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
        */
        RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();
        
        rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE); //diff
        rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        
        rsaPrivateKeyTemplate.getId().setByteArrayValue(keyID.getBytes());
        rsaPrivateKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());

        return session.unwrapKey(mechanism, unwrappingKey, wrappedKey, rsaPrivateKeyTemplate);
    }

    public AESSecretKey genAESKey(String keyID, int size, Session session, boolean isToken, boolean isSensitive) throws TokenException {

        Mechanism keyGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);
        AESSecretKey secretKeyTemplate = new AESSecretKey();
        /*
        secretKeyTemplate.getValueLen().setLongValue(new Long(size / 8));
        secretKeyTemplate.getSensitive().setBooleanValue(isSensitive);
        secretKeyTemplate.getToken().setBooleanValue(isToken);              // not  store in hsm
        secretKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
        //secretKeyTemplate.getExtractable().setBooleanValue(Boolean.FALSE);

        //add for trident
        secretKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE); // acb
        secretKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE); // acb

        secretKeyTemplate.getModifiable().setBooleanValue(Boolean.FALSE);
        secretKeyTemplate.getId().setByteArrayValue(keyID.getBytes());
        secretKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());

        //add for trident
        secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getKeyType().setLongValue(PKCS11Constants.CKK_AES);
        secretKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_SECRET_KEY);
        */
        
        secretKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_SECRET_KEY);
        secretKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getKeyType().setLongValue(PKCS11Constants.CKK_AES);
        //secretKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getValueLen().setLongValue(new Long(size / 8));
        secretKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());
        secretKeyTemplate.getId().setByteArrayValue(keyID.getBytes());
        secretKeyTemplate.getTrusted().setBooleanValue(Boolean.TRUE);
        
        AESSecretKey secretKey = (AESSecretKey) session.generateKey(keyGenerationMechanism, secretKeyTemplate);
        // return secretKey.getValue().getByteArrayValue();
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

        Mechanism keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_EC_KEY_PAIR_GEN);
        ECDSAPublicKey ecdsaPublicKeyTemplate = new ECDSAPublicKey();
        ECDSAPrivateKey ecdsaPrivateKeyTemplate = new ECDSAPrivateKey();

        setKeyAttributes(keyID, keyLabel, PKCS11Constants.CKK_EC, ecdsaPublicKeyTemplate, ecdsaPrivateKeyTemplate);

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

        Mechanism keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
        
        RSAPublicKey rsaPublicKeyTemplate = new RSAPublicKey();
        
        byte[] publicExponentBytes = {0x01, 0x00, 0x01}; // 2^16 + 1
        if (publicExponent != null) {
            publicExponentBytes = bigToByteArray(publicExponent);
        }
        
        rsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        rsaPublicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        rsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
        rsaPublicKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
        rsaPublicKeyTemplate.getModulusBits().setLongValue(new Long(size));
        rsaPublicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
        
        rsaPublicKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());
        rsaPublicKeyTemplate.getId().setByteArrayValue(id);
        
        RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();
        
        rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE); //diff
        rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        
        rsaPrivateKeyTemplate.getId().setByteArrayValue(id);
        rsaPrivateKeyTemplate.getLabel().setCharArrayValue(keyID.toCharArray());
        
        //rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
        //rsaPrivateKeyTemplate.getDerive().setBooleanValue(Boolean.FALSE);
        //rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
        
        /*
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

        //add for trident
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
*/
        return session.generateKeyPair(keyPairGenerationMechanism, rsaPublicKeyTemplate, rsaPrivateKeyTemplate);
    }
    
    private byte[] bigToByteArray(BigInteger x) {
        String hex = x.toString(16);
        if (hex.length() % 2 != 0) {
            hex = '0' + hex;
        }
        return DatatypeConverter.parseHexBinary(hex);
    }
}
