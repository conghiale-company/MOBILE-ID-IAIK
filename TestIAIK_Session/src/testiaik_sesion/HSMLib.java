/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package testiaik_sesion;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.Certificate;
import iaik.pkcs.pkcs11.objects.CharArrayAttribute;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author DELL
 */
public class HSMLib {

    private static String LIBS_WRAPPER = "libpkcs11wrapper";
    private static String PATH32 = "/wrapper32/";
    private static String PATH64 = "/wrapper64/";
    private static Module module_;
    private static Slot[] slots_;
    private static Token token_;
    protected static Session session_;

    private boolean loaded = false;
    private boolean logged = false;
    private boolean connected = false;

    private static int MAX_OBJS = 100;

    public boolean init(String pkcs11Library) throws Exception {
        String dllwrapper;
        dllwrapper = loadDll(LIBS_WRAPPER);
        module_ = Module.getInstance(pkcs11Library, dllwrapper);
        module_.initialize(new DefaultInitializeArgs());
        loaded = true;
        return true;
    }

    private String loadDll(String name) throws IOException {
        String filename = name;
        if (System.getProperty("sun.arch.data.model").compareTo("32") == 0) {
            name = PATH32 + name + ".so";
        } else {
            name = PATH64 + name + ".so";
        }

        InputStream in = HSMLib.class.getResourceAsStream(name);

        byte[] buffer = new byte[1024];
        int read = -1;
        File temp = File.createTempFile(filename, ".so", new File(System.getProperty("java.io.tmpdir")));
        FileOutputStream fos = new FileOutputStream(temp);

        while ((read = in.read(buffer)) != -1) {
            fos.write(buffer, 0, read);
        }
        fos.close();
        in.close();
        //System.out.println("libpkcs11wrapper path: " + temp.getAbsolutePath());
        return temp.getAbsolutePath();
    }

    public boolean connect() throws Exception {
        slots_ = module_.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
        //token_ = slots_[0].getToken();
        //session_ = token_.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION, null, null);
        connected = true;
        //return session_.getSessionHandle();
        return true;
    }

    public void showAvailableSlot() {
        if (connected) {
            System.out.println("Available slots: " + slots_.length);
            for (Slot slot : slots_) {
                System.out.println("\tSlotID: " + slot.getSlotID());
                //System.out.println("\tSlotDescription: " + slot.getSlotInfo().getSlotDescription());
                try {
                    System.out.println("\tSlotLabel: " + slot.getToken().getTokenInfo().getLabel());
                } catch (TokenException e) {
                    e.printStackTrace();
                }
                System.out.println();
            }
            return;
        }
    }

    public long openSession(int slotID) throws TokenException {
        token_ = slots_[slotID].getToken();
        session_ = token_.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION, null, null);
        return session_.getSessionHandle();
    }

    public boolean login(char[] password) throws TokenException {
        if (logged) {
            session_.logout();
        }
        session_ = token_.openSession(
                Token.SessionType.SERIAL_SESSION,
                Token.SessionReadWriteBehavior.RW_SESSION, null, null);
        char[] pin = password;
        session_.login(Session.UserType.USER, pin);
        logged = true;
        return true;
    }

    public void listPrivateKey() throws TokenException {
        RSAPrivateKey e = new RSAPrivateKey();
        //RSAPrivateKey temp_key = null;
        //e.getId().setByteArrayValue(DatatypeConverter.parseHexBinary(KeyID));
        session_.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_rsaPrivKey = session_.findObjects(MAX_OBJS);
        session_.findObjectsFinal();

        List list = new ArrayList<RSAPrivateKey>();
        if (temp_rsaPrivKey != null && temp_rsaPrivKey.length > 0 && temp_rsaPrivKey[0] != null) {
            list.add((RSAPrivateKey) temp_rsaPrivKey[0]);
        }
        if (list.isEmpty()) {
            System.out.println("No private object found");
        } else {
            System.out.println(list.size() + " private object found");
            for (Object k : list) {
                RSAPrivateKey key = (RSAPrivateKey) k;
                ByteArrayAttribute keyID = key.getId();
                CharArrayAttribute keyLabel = key.getLabel();
                ByteArrayAttribute keySubject = key.getSubject();
                ByteArrayAttribute keyModulus = key.getModulus();

                String keyIDStr = "null";
                if (keyID != null) {
                    byte[] rawKeyID = keyID.getByteArrayValue();
                    if (rawKeyID != null) {
                        keyIDStr = DatatypeConverter.printHexBinary(rawKeyID);
                    }
                }

                String keyLabelStr = "null";
                if (keyLabel != null) {
                    char[] rawKeyLabel = keyLabel.getCharArrayValue();
                    if (rawKeyLabel != null) {
                        keyLabelStr = String.valueOf(rawKeyLabel);
                    }
                }

                String keySubjectStr = "null";
                if (keySubject != null) {
                    byte[] rawKeySubject = keySubject.getByteArrayValue();
                    if (rawKeySubject != null) {
                        keySubjectStr = DatatypeConverter.printHexBinary(rawKeySubject);
                    }
                }

                String keyModulusStr = "null";
                if (keyModulus != null) {
                    byte[] rawKeyModulus = keyModulus.getByteArrayValue();
                    if (rawKeyModulus != null) {
                        keyModulusStr = DatatypeConverter.printHexBinary(rawKeyModulus);
                    }
                }
                System.out.println("KEY_ID=" + keyIDStr);
                System.out.println("KEY_LABEL=" + keyLabelStr);
                System.out.println("KEY_SUBJECT=" + keySubjectStr);
                System.out.println("KEY_MODULUS=" + keyModulusStr);
            }
        }
    }

    public void listPublicKey() throws TokenException {
        RSAPublicKey e = new RSAPublicKey();
        //RSAPublicKey temp_key = null;
        //e.getId().setByteArrayValue(DatatypeConverter.parseHexBinary(KeyID));
        session_.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_rsaPubKey = session_.findObjects(MAX_OBJS);
        session_.findObjectsFinal();

        List list = new ArrayList<RSAPublicKey>();
        if (temp_rsaPubKey != null && temp_rsaPubKey.length > 0 && temp_rsaPubKey[0] != null) {
            list.add((RSAPublicKey) temp_rsaPubKey[0]);
        }
        if (list.isEmpty()) {
            System.out.println("No public object found");
        } else {
            System.out.println(list.size() + " public object found");
            for (Object k : list) {
                RSAPublicKey key = (RSAPublicKey) k;
                ByteArrayAttribute keyID = key.getId();
                CharArrayAttribute keyLabel = key.getLabel();
                ByteArrayAttribute keySubject = key.getSubject();
                ByteArrayAttribute keyModulus = key.getModulus();

                String keyIDStr = "null";
                if (keyID != null) {
                    byte[] rawKeyID = keyID.getByteArrayValue();
                    if (rawKeyID != null) {
                        keyIDStr = DatatypeConverter.printHexBinary(rawKeyID);
                    }
                }

                String keyLabelStr = "null";
                if (keyLabel != null) {
                    char[] rawKeyLabel = keyLabel.getCharArrayValue();
                    if (rawKeyLabel != null) {
                        keyLabelStr = String.valueOf(rawKeyLabel);
                    }
                }

                String keySubjectStr = "null";
                if (keySubject != null) {
                    byte[] rawKeySubject = keySubject.getByteArrayValue();
                    if (rawKeySubject != null) {
                        keySubjectStr = DatatypeConverter.printHexBinary(rawKeySubject);
                    }
                }

                String keyModulusStr = "null";
                if (keyModulus != null) {
                    byte[] rawKeyModulus = keyModulus.getByteArrayValue();
                    if (rawKeyModulus != null) {
                        keyModulusStr = DatatypeConverter.printHexBinary(rawKeyModulus);
                    }
                }
                System.out.println("KEY_ID=" + keyIDStr);
                System.out.println("KEY_LABEL=" + keyLabelStr);
                System.out.println("KEY_SUBJECT=" + keySubjectStr);
                System.out.println("KEY_MODULUS=" + keyModulusStr);
            }
        }
    }

    public void listCertificate() throws TokenException {
        Certificate e = new Certificate();
        //RSAPublicKey temp_key = null;
        //e.getId().setByteArrayValue(DatatypeConverter.parseHexBinary(KeyID));
        session_.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_cert = session_.findObjects(MAX_OBJS);
        session_.findObjectsFinal();

        List list = new ArrayList<Certificate>();
        if (temp_cert != null && temp_cert.length > 0 && temp_cert[0] != null) {
            list.add((Certificate) temp_cert[0]);
        }
        if (list.isEmpty()) {
            System.out.println("No certificate object found");
        } else {
            System.out.println(list.size() + " certificate object found");
            for (Object k : list) {
                X509PublicKeyCertificate c = (X509PublicKeyCertificate) k;
                ByteArrayAttribute keyID = c.getId();
                CharArrayAttribute keyLabel = c.getLabel();
                ByteArrayAttribute keySubject = c.getSubject();
                //ByteArrayAttribute keyModulus = c.getModulus();

                String keyIDStr = "null";
                if (keyID != null) {
                    byte[] rawKeyID = keyID.getByteArrayValue();
                    if (rawKeyID != null) {
                        keyIDStr = DatatypeConverter.printHexBinary(rawKeyID);
                    }
                }

                String keyLabelStr = "null";
                if (keyLabel != null) {
                    char[] rawKeyLabel = keyLabel.getCharArrayValue();
                    if (rawKeyLabel != null) {
                        keyLabelStr = String.valueOf(rawKeyLabel);
                    }
                }

                String keySubjectStr = "null";
                if (keySubject != null) {
                    byte[] rawKeySubject = keySubject.getByteArrayValue();
                    if (rawKeySubject != null) {
                        keySubjectStr = DatatypeConverter.printHexBinary(rawKeySubject);
                    }
                }

//                String keyModulusStr = "null";
//                if (keyModulus != null) {
//                    byte[] rawKeyModulus = keyModulus.getByteArrayValue();
//                    if (rawKeyModulus != null) {
//                        keyModulusStr = DatatypeConverter.printHexBinary(rawKeyModulus);
//                    }
//                }
                System.out.println("KEY_ID=" + keyIDStr);
                System.out.println("KEY_LABEL=" + keyLabelStr);
                System.out.println("KEY_SUBJECT=" + keySubjectStr);
//                System.out.println("KEY_MODULUS=" + keyModulusStr);
            }
        }
    }

    public void listAESKey() throws TokenException {
        AESSecretKey e = new AESSecretKey();
        session_.findObjectsInit(e);
        iaik.pkcs.pkcs11.objects.Object[] temp_aes = session_.findObjects(MAX_OBJS);
        session_.findObjectsFinal();

        List list = new ArrayList<AESSecretKey>();
        if (temp_aes != null && temp_aes.length > 0 && temp_aes[0] != null) {
            list.add((AESSecretKey) temp_aes[0]);
        }
        if (list.isEmpty()) {
            System.out.println("No aes object found");
        } else {
            System.out.println(list.size() + " aes object found");
            for (Object k : list) {
                AESSecretKey key = (AESSecretKey) k;
                ByteArrayAttribute keyID = key.getId();
                CharArrayAttribute keyLabel = key.getLabel();
//                ByteArrayAttribute keySubject = key.getSubject();
//                ByteArrayAttribute keyModulus = key.getModulus();

                String keyIDStr = "null";
                if (keyID != null) {
                    byte[] rawKeyID = keyID.getByteArrayValue();
                    if (rawKeyID != null) {
                        keyIDStr = DatatypeConverter.printHexBinary(rawKeyID);
                    }
                }

                String keyLabelStr = "null";
                if (keyLabel != null) {
                    char[] rawKeyLabel = keyLabel.getCharArrayValue();
                    if (rawKeyLabel != null) {
                        keyLabelStr = String.valueOf(rawKeyLabel);
                    }
                }

//                String keySubjectStr = "null";
//                if (keySubject != null) {
//                    byte[] rawKeySubject = keySubject.getByteArrayValue();
//                    if (rawKeySubject != null) {
//                        keySubjectStr = DatatypeConverter.printHexBinary(rawKeySubject);
//                    }
//                }
//
//                String keyModulusStr = "null";
//                if (keyModulus != null) {
//                    byte[] rawKeyModulus = keyModulus.getByteArrayValue();
//                    if (rawKeyModulus != null) {
//                        keyModulusStr = DatatypeConverter.printHexBinary(rawKeyModulus);
//                    }
//                }
                System.out.println("KEY_ID=" + keyIDStr);
                System.out.println("KEY_LABEL=" + keyLabelStr);
//                System.out.println("KEY_SUBJECT=" + keySubjectStr);
//                System.out.println("KEY_MODULUS=" + keyModulusStr);
            }
        }
    }

    public void generateAESKey(String keyName) throws Exception {
        Mechanism keyGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);
        AESSecretKey aesKey = new AESSecretKey();
        aesKey.getValueLen().setLongValue(new Long(32));
        aesKey.getLabel().setCharArrayValue(keyName.toCharArray());
        aesKey.getToken().setBooleanValue(Boolean.FALSE); // temporary session key
        aesKey.getSign().setBooleanValue(Boolean.FALSE);//
        aesKey.getVerify().setBooleanValue(Boolean.FALSE);//
        aesKey.getEncrypt().setBooleanValue(Boolean.TRUE);
        aesKey.getUnwrap().setBooleanValue(Boolean.TRUE);
        aesKey.getPrivate().setBooleanValue(Boolean.TRUE); // only accessible after log-in
        AESSecretKey aesWrappingKey = (AESSecretKey) session_.generateKey(keyGenerationMechanism, aesKey);
    }

    public void findCertificateWithLabel(String label) throws TokenException {
        PKCS11 pkcs11 = module_.getPKCS11Module();

        CK_ATTRIBUTE[] findCerAttrList = new CK_ATTRIBUTE[2];
        findCerAttrList[0] = new CK_ATTRIBUTE();
        findCerAttrList[0].type = PKCS11Constants.CKA_CLASS;
        findCerAttrList[0].pValue = PKCS11Constants.CKO_CERTIFICATE;

        findCerAttrList[1] = new CK_ATTRIBUTE();
        findCerAttrList[1].type = PKCS11Constants.CKA_LABEL;
        findCerAttrList[1].pValue = label.toCharArray();

        pkcs11.C_FindObjectsInit(session_.getSessionHandle(), findCerAttrList, true);
        long[] handles = pkcs11.C_FindObjects(session_.getSessionHandle(), MAX_OBJS);
        pkcs11.C_FindObjectsFinal(session_.getSessionHandle());

        if (handles != null && handles.length != 0) {
            if (handles.length != 1) {
                throw new TokenException("more than 1 certificate found with label=" + label);
            }

            CK_ATTRIBUTE[] getCKAValueAttrList = new CK_ATTRIBUTE[1];
            getCKAValueAttrList[0] = new CK_ATTRIBUTE();
            getCKAValueAttrList[0].type = PKCS11Constants.CKA_ID;

            pkcs11.C_GetAttributeValue(session_.getSessionHandle(), handles[0], getCKAValueAttrList, true);
            byte[] ckaID = (byte[]) getCKAValueAttrList[0].pValue;
            System.out.println("CKA_ID=" + DatatypeConverter.printHexBinary(ckaID));
        } else {
            throw new TokenException("no certificate found with label=" + label);
        }
    }

}
