/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package vn.mobileid.testiaik;

import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Random;
import java.util.TimeZone;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import vn.mobileid.testiaik.hsm.HSMLib;
import vn.mobileid.testiaik.hsm.HSMManager;
import vn.mobileid.testiaik.hsm.HSMManagerImp;
import vn.mobileid.testiaik.utils.Utils;

/**
 *
 * @author DELL
 */
public class TestIAIK {

    static BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

    //static String PKCS11_MODULE = "/usr/lib/libcknfast.so";

    private static void printUsage() {
        System.out.println("Functions: ");
        System.out.println("\t 1.init");
        System.out.println("\t 2.connect");
        System.out.println("\t 3.show slot");
        System.out.println("\t 4.open session");
        System.out.println("\t 5.login");
        System.out.println("\t 6.list private key");
        System.out.println("\t 7.list public key");
        System.out.println("\t 8.list certificate");
        System.out.println("\t 9.list aes key");
        System.out.println("\t 10.findCertificateWithLabel");
        System.out.println("\t 11.testKeyWrapping");
        System.out.println("\t 12.test sign");
        System.out.println("\t *.quit");

    }

    public static void main(String[] args) throws Exception {
        HSMLib hsm = new HSMLib();
        boolean rs;
        boolean loop = true;
        int resultCode = 0;
        do {
            printUsage();
            System.out.print("Choice: ");
            String choice = reader.readLine();
            if (isNumeric(choice)) {
                resultCode = Integer.parseInt(choice);
            } else {
                break;
            }
            switch (resultCode) {
                case 1:
                    System.out.print("PKCS#11 module: ");
                    String p11Module = reader.readLine();
                    if (hsm.init(p11Module)) {
                        System.out.println("inited");
                    } else {
                        System.out.println("failed");
                    }
                    break;
                case 2:
                    if (hsm.connect()) {
                        System.out.println("connected");
                    } else {
                        System.out.println("failed");
                    }
                    break;
                case 3:
                    hsm.showAvailableSlot();
                    break;
                case 4:
                    System.out.print("Slot Index: ");
                    String slotIndex = reader.readLine();
                    long sessionHandle = hsm.openSession(Integer.parseInt(slotIndex));
                    System.out.println("sessionHandle=" + sessionHandle);
                    break;
                case 5:
                    System.out.print("pin: ");
                    String pin = reader.readLine();
                    rs = hsm.login(pin.toCharArray());
                    System.out.println("login result=" + rs);
                    break;
                case 6:
                    hsm.listPrivateKey();
                    break;
                case 7:
                    hsm.listPublicKey();
                    break;
                case 8:
                    hsm.listCertificate();
                    break;
                case 9:
                    hsm.listAESKey();
                    break;
                case 10:
                    System.out.print("alias: ");
                    String alias = reader.readLine();
                    hsm.findCertificateWithLabel(alias);
                    break;
                case 11:
                    testKeyWrapping();
                    break;
                case 12:
                    testSign();
                    break;
                default:
                    loop = false;
                    break;
            }
        } while (loop);
    }

    static boolean isNumeric(String s) {
        try {
            Integer.parseInt(s);
            return true;
        } catch (NumberFormatException e) {

        }
        return false;
    }

    static void testKeyWrapping() throws Exception {
        //int hsm
//        String p11Lib = "/usr/lib64/pkcs11/yubihsm_pkcs11.so";
//        String p11Wrapper = "/root/libpkcs11wrapper.so";
//        int slotId = 0;
//        String pin = "0001password";
        /*
        System.out.print("p11 so file: ");
        String sofile = reader.readLine();
        System.out.print("wrapper file: ");
        String wrapper = reader.readLine();
        System.out.print("slot: ");
        String slotstr = reader.readLine();
        System.out.print("pin: ");
        String pin = reader.readLine();
        System.out.print("CKM_AES_CBC/CKM_AES_CBC_PAD: ");
        String aesMode = reader.readLine();
        long mode = PKCS11Constants.CKM_AES_CBC;
        if (aesMode.equalsIgnoreCase("CKM_AES_CBC")) {
            System.out.println("Using mode CKM_AES_CBC...");
        } else {
            mode = PKCS11Constants.CKM_AES_CBC_PAD;
            System.out.println("Using mode CKM_AES_CBC_PAD...");
        }
        System.out.println("Using ");
        */
        
        String sofile = "/usr/lib/libcknfast.so";
        String wrapper = "/root/libpkcs11wrapper.so";
        String slotstr = "761406615";
        String pin = "123456";
        
        long mode = PKCS11Constants.CKM_AES_CBC_PAD;

        HSMManager hsmManager = HSMManagerImp.getInstance(sofile, wrapper, Integer.parseInt(slotstr), pin);
        String aesKeyName = getRandomKeyID();
        AESSecretKey aes = hsmManager.genAESSecretKey(
                aesKeyName,
                256,
                true);
        if (aes != null) {
            System.out.println("generate aes key successfully with name=" + aesKeyName);
            String rsaKeyName = getRandomKeyID();
            iaik.pkcs.pkcs11.objects.KeyPair kp = hsmManager.GenerateRSAKeyPair(rsaKeyName, 2048, 16);
            System.out.println("generate rsa key successfully with name=" + rsaKeyName);

            System.out.println("wrapping...");

            byte[] iv = Utils.genRandomArray(16);
            System.out.println("PrivateKey: " + kp.getPrivateKey());
            byte[] rawKeyWrapped = hsmManager.wrapKey(kp.getPrivateKey(), aes, mode, iv);
            System.out.println("key wrapped: " + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(rawKeyWrapped));

            System.out.println("test signing...");
            byte[] data2sign = new byte[32];
            data2sign = paddingSHA256OID(data2sign);
            byte[] signature = hsmManager.signWithPrivateKey(
                    PKCS11Constants.CKM_RSA_PKCS,
                    data2sign,
                    kp.getPrivateKey());
            System.out.println("signature=" + Base64.getEncoder().encodeToString(signature));
            System.out.println("deleting...");
            Key hsmPubKey = kp.getPublicKey();
            Key hsmPriKey = kp.getPrivateKey();
            if (hsmPubKey != null) {
                hsmManager.deleteKey(hsmPubKey);
                System.out.println("\tdelete publickey " + rsaKeyName + " successfully");
            }
            if (hsmPriKey != null) {
                hsmManager.deleteKey(hsmPriKey);
                System.out.println("\tdelete siging key " + rsaKeyName + " successfully");
            }
            System.out.println("unwrapping...");
            Key signingKey = hsmManager.unWrapKey(
                    rawKeyWrapped,
                    aes,
                    mode,
                    iv,
                    Key.KeyType.RSA,
                    rsaKeyName,
                    true);
            System.out.println("unwrapping successfully");
            System.out.println("test signing...");
            data2sign = new byte[32];
            data2sign = paddingSHA256OID(data2sign);
            signature = hsmManager.signWithPrivateKey(
                    PKCS11Constants.CKM_RSA_PKCS,
                    data2sign,
                    signingKey);
            System.out.println("signature=" + Base64.getEncoder().encodeToString(signature));
            System.out.println("deleting...");
            hsmManager.deleteKey(signingKey);
            System.out.println("\tdelete siging key " + rsaKeyName + " successfully");
            hsmManager.deleteKey(aes);
            System.out.println("\tdelete aes key " + rsaKeyName + " successfully");
        }
    }

    static void testSign() throws Exception {
        System.out.print("p11 so file: ");
        String sofile = reader.readLine();
        System.out.print("wrapper file: ");
        String wrapper = reader.readLine();
        System.out.print("slot: ");
        String slotstr = reader.readLine();
        System.out.print("pin: ");
        String pin = reader.readLine();
        System.out.print("keyID: ");
        String keyID = reader.readLine();

        sofile = "/usr/lib/libcs_pkcs11_R2.so";
        wrapper = "/root/libpkcs11wrapper.so";
        slotstr = "2";
        pin = "12345678";
        keyID = "343334313332326433323330333233313330333933323337";

        HSMManager hsmManager = HSMManagerImp.getInstance(sofile, wrapper, Integer.parseInt(slotstr), pin);

        byte[] d = new byte[20];
        Key privateKey = hsmManager.getPrivateKeyWithKeyID(keyID);
        if (privateKey == null) {
            throw new Exception("not found private key");
        }
        for (int i = 0; i < 400; i++) {
            byte[] s = hsmManager.sign(PKCS11Constants.CKM_SHA256_RSA_PKCS, d, privateKey);
            System.out.println("sign " + i + ": " + Base64.getEncoder().encodeToString(s));
        }
    }

    private static String getRandomKeyID() {
        String keyID = null;
        try {
            //SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss");
            //sdf.setTimeZone(TimeZone.getTimeZone(System.getProperty("user.timezone")));
            //keyID = sdf.format(new Date()).concat(UUID.randomUUID().toString().replace("-", ""));
            //trident hsm issue, key name length limited
            SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss");
            sdf.setTimeZone(TimeZone.getTimeZone(System.getProperty("user.timezone")));
            keyID = sdf.format(new Date()) + generateOneTimePassword(8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return keyID.toUpperCase();
    }

    public static String generateOneTimePassword(int len) {
        String numbers = "0123456789";
        Random rndm_method = new Random();
        char[] otp = new char[len];
        for (int i = 0; i < len; i++) {
            otp[i] = numbers.charAt(rndm_method.nextInt(numbers.length()));
        }
        return new String(otp);
    }

    public static byte[] paddingSHA256OID(byte[] hashedData) throws Exception {
        DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find("SHA-256");
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }
}
