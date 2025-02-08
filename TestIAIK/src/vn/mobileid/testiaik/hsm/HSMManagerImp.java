package vn.mobileid.testiaik.hsm;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.concurrent.locks.ReentrantLock;

import javax.xml.bind.DatatypeConverter;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class HSMManagerImp implements HSMManager {

    private static final Logger LOG = LogManager.getLogger(HSMManagerImp.class);

    private boolean login;
    private boolean loginSo;

    private static HSMManager instance = null;
    public HSMFunction hsmFunction;
    //public static ConcurrentHashMap<String, Session> sessionManager;
    private String passsword;
    private Session sessionLogin;
    /*private static String LIBS_WRAPPER = "PKCS11Wrapper";
     private static String PATH32 = "wrapper32/";
     private static String PATH64 = "wrapper64/";*/
    private int slotNumber;

    private static ReentrantLock lock = new ReentrantLock();

    public HSMFunction getHsmFunction() {
        return hsmFunction;
    }

    public HSMManagerImp(String pkcs11LibName, String pkcs11Wrapper, int slot, String password) throws IOException, TokenException {
        // TODO Auto-generated constructor stub
        hsmFunction = new HSMFunction();
        //init(pkcs11LibName, pkcs11Wrapper);
        hsmFunction.loadDll(pkcs11LibName, pkcs11Wrapper);
        this.slotNumber = slot;

        this.login = false;

        this.passsword = password;
    }

    @SuppressWarnings("unused")
    private void init(String dllName, String wrapper) throws Throwable {
        // TODO Auto-generated method stub
        //String pkcs11Wrapper = loadWrapper(LIBS_WRAPPER);
        String pkcs11Wrapper = wrapper;
        //logger.debug("LIBS_WRAPPER: " + pkcs11Wrapper);
        hsmFunction.loadDll(dllName, pkcs11Wrapper);
    }

    public static HSMManager getInstance(String pkcs11LibName, String pkcs11Wrapper, int slot, String password) {
//        if (instance != null) {
//            return instance;
//        }
//        lock.lock();
//        if (instance != null) {
//            lock.unlock();
//            return instance;
//        }
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

    public boolean loginHSM(boolean asUser) throws TokenException {
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
            hsmFunction.login(sessionLogin, passsword, asUser);
            if (asUser) {
                login = true;
            } else {
                loginSo = true;
            }
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
            throw e;
        } finally {
            lock.unlock();
        }
        return (login || loginSo);
    }

    public boolean logoutHSM(boolean asUser) throws TokenException {
        // TODO Auto-generated method stub
        boolean status1 = hsmFunction.logout(sessionLogin);
        if (status1) {
            if (asUser) {
                login = false;
            } else {
                loginSo = false;
            }
            sessionLogin.closeSession();
            return true;
        } else {
            return false;
        }
    }

    private boolean isLogin() {
        return login;
    }

    private boolean isLoginSo() {
        return loginSo;
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
        // TODO Auto-generated method stub
        boolean res = false;
        try {
            res = logoutHSM(true);
        } catch (TokenException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            if (hsmFunction.disconnectToken()) {
                instance = null;
            }
        }

        return res;
    }

    @Override
    public String encryptDataWithKeyID(String plaintext, String KeyID)
            throws TokenException, UnsupportedEncodingException {
        // TODO Auto-generated method stub		
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);

            RSAPublicKey publickey = hsmFunction.getPublicKeyByID(KeyID, session);
            if (publickey == null) {
                session.closeSession();
                return "0";
            } else {
                //if don't opnen session????
                //session = hsmFunction.openSession(null, new PKCS11NotifyImpl());

                byte[] enc = hsmFunction.encrypt(plaintext, publickey, session);
                String base64enc = DatatypeConverter.printBase64Binary(enc);

                session.closeSession();

                return base64enc;
            }
        } else {
            return "2";
        }

    }

    @Override
    public byte[] encryptDataWithKeyID(byte[] data, String KeyID) throws TokenException, UnsupportedEncodingException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);

            RSAPublicKey publickey = hsmFunction.getPublicKeyByID(KeyID, session);
            if (publickey == null) {
                session.closeSession();
                return null;
            } else {
                //if don't opnen session????
                //session = hsmFunction.openSession(null, new PKCS11NotifyImpl());

                byte[] enc = hsmFunction.encrypt(data, publickey, session);
                session.closeSession();

                return enc;
            }
        } else {
            return null;
        }

    }

    @Override
    public String decryptDataWithKeyID(String encText, String KeyID) throws TokenException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            try {
                Session session = hsmFunction.openSession(slotNumber);

                RSAPrivateKey privatekey = hsmFunction.getPrivateKeyByID(KeyID, session);
                if (privatekey == null) {
                    session.closeSession();
                    return "0";
                }
                byte[] e = DatatypeConverter.parseBase64Binary(encText);
                byte[] dec = hsmFunction.decryptData(e, privatekey, session);
                String plaintext = new String(dec, "UTF-8");

                session.closeSession();
                return plaintext;
            } catch (IOException var16) {
                var16.printStackTrace();
                return "1";
            }
        } else {
            return "2";
        }

    }

    @Override
    public byte[] decryptDataWithKeyID(byte[] dataEncoded, String KeyID) throws TokenException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);

            RSAPrivateKey privatekey = hsmFunction.getPrivateKeyByID(KeyID, session);
            if (privatekey == null) {
                session.closeSession();
                return null;
            }
            byte[] data = hsmFunction.decryptData(dataEncoded, privatekey, session);

            session.closeSession();
            return data;
        } else {
            return null;
        }
    }

    @Override
    public byte[] unWrapKey(byte[] secretKeyWrapped, String hsmKeyID) throws TokenException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            //byte[] wrappedKeyRaw = DatatypeConverter.parseBase64Binary(wrappedKey);
            // System.out.println("wrappedKeyRaw: " +
            // DatatypeConverter.printHexBinary(wrappedKeyRaw));
            RSAPrivateKey privateKey = hsmFunction.getPrivateKeyByID(hsmKeyID, session);
            privateKey.getUnwrap().setBooleanValue(Boolean.TRUE);
            byte[] rawKeyWrapped = hsmFunction.unwrapAESKey(privateKey, secretKeyWrapped, session);
            session.closeSession();
            return rawKeyWrapped;

        } else {
            return null;
        }

    }

    @Override
    public AESSecretKey genAESSecretKey(int size) throws TokenException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM(true);
        }

        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            AESSecretKey response = hsmFunction.genAESKey(size, session);
            //not close session when crate AES-key
            //session.closeSession();
            return response;
        }
        return null;
    }

    @Override
    public byte[] wrapKey(AESSecretKey scSysKey, String hsmKeyID) throws TokenException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            RSAPublicKey publicKey = hsmFunction.getPublicKeyByID(hsmKeyID, session);
            publicKey.getWrap().setBooleanValue(Boolean.TRUE);
            byte[] rawKeyWrapped = hsmFunction.wrapKey((Key) publicKey, (Key) scSysKey, session);
            //String base64WrappedKey = DatatypeConverter.printBase64Binary(rawKeyWrapped);			
            session.closeSession();

            return rawKeyWrapped;
        } else {
            return null;
        }
    }

    @Override
    public byte[] wrapKey(Key wrappedKey, Key wrappingKey, long mode, byte[] iv) throws TokenException {
        if (!isLogin()) {
            loginHSM(true);
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
        } else {
            return null;
        }
    }

    @Override
    public boolean hasKeyID(String keyID) throws TokenException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            RSAPublicKey publicKey = hsmFunction.getPublicKeyByID(keyID, session);
            session.closeSession();
            return publicKey != null;
        } else {
            return false;
        }
    }

    @Override
    public byte[] signWithKeyID(long pkcs11MechanismCode, byte[] data, String KeyID)
            throws PKCS11Exception, TokenException, UnsupportedEncodingException, HSMException {
        // TODO Auto-generated method stub

        if (!isLogin()) {

            loginHSM(true);
        }
        if (isLogin()) {

            Session session = hsmFunction.openSession(slotNumber);
            RSAPrivateKey privateKey = hsmFunction.getPrivateKeyByID(KeyID, session);
            if (privateKey == null) {
                session.closeSession();
                throw new HSMException("HSM not found key for id " + KeyID);
            }

            byte[] signed = hsmFunction.sign(pkcs11MechanismCode, data, privateKey, session);

            session.closeSession();
            return signed;
        }
        return null;
    }

    @Override
    public byte[] genAndWrapAESSecretKey(int size, String hsmKeyID) throws Exception {
        // TODO Auto-generated method stub		
        byte[] rawKeyWrapped = null;

        if (!isLogin()) {

            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            AESSecretKey aesKey = hsmFunction.genAESKey(size, session);

            RSAPublicKey publicKey = hsmFunction.getPublicKeyByID(hsmKeyID, session);
            publicKey.getWrap().setBooleanValue(Boolean.TRUE);
            rawKeyWrapped = hsmFunction.wrapKey((Key) publicKey, (Key) aesKey, session);

            session.closeSession();
        }

        return rawKeyWrapped;
    }

    @Override
    public byte[] signWithPrivateKey(long pkcs11MechanismCode, byte[] plaintext, Key privateKey)
            throws PKCS11Exception, TokenException, UnsupportedEncodingException {
        // TODO Auto-generated method stub
        if (!isLogin()) {

            loginHSM(true);
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

    @Override
    public byte[] signWithPrivateKey20210224(long pkcs11MechanismCode, byte[] plaintext, RSAPrivateKey privateKey)
            throws PKCS11Exception, TokenException, UnsupportedEncodingException {
        // TODO Auto-generated method stub
        if (!isLogin()) {

            loginHSM(true);
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

    @Override
    public RSAPrivateKey getPrivateKeyWithKeyID(String keyId) throws TokenException {
        // TODO Auto-generated method stub		
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            RSAPrivateKey privateKey = hsmFunction.getPrivateKeyByID(keyId, session);
            session.closeSession();
            return privateKey;

        } else {
            return null;
        }
    }

    @Override
    public Key getKeyWithKeyID(String keyId) throws TokenException {
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            Key key = hsmFunction.getKeyByID(keyId, session);
            session.closeSession();
            return key;
        } else {
            return null;
        }
    }

    @Override
    public Key unWrapKey(byte[] secretKeyWrapped, Key wrappingKey, long mode, byte[] iv, Long keyType, String keyID, boolean isToken) throws TokenException {
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            Mechanism mechanism = Mechanism.get(mode);
            if (iv != null) {
                mechanism.setParameters(new InitializationVectorParameters(iv));
            }
            Key wrappedKey = hsmFunction.unwrapKey(wrappingKey, secretKeyWrapped, session, mechanism, keyType, keyID, isToken);
            session.closeSession();
            return wrappedKey;

        } else {
            return null;
        }
    }

    @Override
    public AESSecretKey genAESSecretKey(String keyID, int size, boolean isToken) throws TokenException {
        if (!isLoginSo()) {
            loginHSM(false);
        }
        if (isLoginSo()) {
            Session session = hsmFunction.openSession(slotNumber);
            AESSecretKey response = hsmFunction.genAESKey(keyID, size, session, isToken, true);
            //not close session when crate AES-key
            session.closeSession();
            logoutHSM(false);
            return response;
        }
        return null;
    }

    @Override
    public boolean deleteKeyPair(KeyPair keyPair) throws TokenException {
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            hsmFunction.deleteKey(keyPair.getPrivateKey(), session);
            hsmFunction.deleteKey(keyPair.getPublicKey(), session);
            session.closeSession();
            return true;
        } else {
            return false;
        }
    }

    @Override
    public boolean deleteKey(Key key) throws TokenException {
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            hsmFunction.deleteKey(key, session);
            session.closeSession();
            return true;
        } else {
            return false;
        }
    }

    @Override
    public List<ECDSAPrivateKey> getECKeyByID(String keyID) throws Exception {
        // TODO Auto-generated method stub
        List<ECDSAPrivateKey> keys = new ArrayList<>();
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keys = hsmFunction.getECKeyByID(session, keyID);
            session.closeSession();
        } else {
            throw new Exception("Cannot login to HSM");
        }
        return keys;
    }

    @Override
    public List<ECDSAPrivateKey> getECKeyByLabel(String keyLabel) throws Exception {
        // TODO Auto-generated method stub
        List<ECDSAPrivateKey> keys = new ArrayList<>();
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keys = hsmFunction.getECKeyByLabel(session, keyLabel);
            session.closeSession();
        } else {
            throw new Exception("Cannot login to HSM");
        }
        return keys;
    }

    @Override
    public List<ECDSAPublicKey> getPublicECKeyByID(String keyID) throws Exception {
        // TODO Auto-generated method stub
        List<ECDSAPublicKey> keys = new ArrayList<>();
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keys = hsmFunction.getPublicECKeyByID(session, keyID);
            session.closeSession();
        } else {
            throw new Exception("Cannot login to HSM");
        }
        return keys;
    }

    @Override
    public List<ECDSAPublicKey> getPublicECKeyByLabel(String keyLabel) throws Exception {
        // TODO Auto-generated method stub
        List<ECDSAPublicKey> keys = new ArrayList<>();
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keys = hsmFunction.getPublicECKeyByLabel(session, keyLabel);
            session.closeSession();
        } else {
            throw new Exception("Cannot login to HSM");
        }
        return keys;
    }

    @Override
    public List<ECDSAPrivateKey> listECKeys() throws Exception {
        // TODO Auto-generated method stub
        List<ECDSAPrivateKey> keys = new ArrayList<>();
        if (!isLogin()) {
            loginHSM(true);
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

    @Override
    public byte[] sign(long pkcs11MechanismCode, byte[] plaintext, Key privateKey)
            throws PKCS11Exception, TokenException, UnsupportedEncodingException {
        // TODO Auto-generated method stub
        if (!isLogin()) {
            loginHSM(true);
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

    @Override
    public boolean idExists(String keyID) throws TokenException {
        boolean isExisted = false;
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            isExisted = hsmFunction.idExists(session, keyID);
            session.closeSession();
            return isExisted;
        }
        return isExisted;
    }

    @Override
    public boolean labelExists(String keyLabel) throws TokenException {
        boolean isExisted = false;
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            isExisted = hsmFunction.labelExists(session, keyLabel);
            session.closeSession();
            return isExisted;
        }
        return isExisted;
    }

    @Override
    public KeyPair genECDSAKeyPair(String keyID, String keyLabel, final ASN1ObjectIdentifier curveId) throws TokenException {
        KeyPair keyPair = null;
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            Session session = hsmFunction.openSession(slotNumber);
            keyPair = hsmFunction.genECDSAKeyPair(keyID, keyLabel, curveId, session);
            session.closeSession();
        }
        return keyPair;
    }

    @Override
    public int removeObjects(String keyID, String keyLabel) throws TokenException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public KeyPair GenerateRSAKeyPair(String keyID, int Keylength, int publicExponent) throws NumberFormatException, NoSuchAlgorithmException, InvalidKeySpecException, TokenException {
        if (!isLogin()) {
            loginHSM(true);
        }
        if (isLogin()) {
            BigInteger exponent = BigInteger.valueOf(2L).shiftLeft(publicExponent - 1).add(BigInteger.ONE);
            if (publicExponent == 0) {
                exponent = null;
            }
            Session session = hsmFunction.openSession(slotNumber);
            KeyPair kp = hsmFunction.genRSAKeyPair(keyID, Keylength, exponent, session);
            session.closeSession();
            return kp;
        } else {
            return null;
        }
    }
}
