/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package testiaik_sesion;

import com.fasterxml.jackson.databind.ObjectMapper;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.TimeZone;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import vn.mobileid.hsm.HSMManager;
import vn.mobileid.hsm.HSMManagerImp;
import vn.mobileid.hsm.HSMManagerImp.KeyType;

/**
 *
 * @author Tan_Hung
 */
public class TestIAIK_Sesion {
    
//    START_TEST
    private static String jwt;
//    END_TEST

    static BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

//    static String PKCS11_MODULE = "/usr/lib/libcs_pkcs11_R2.so";
    static String PKCS11_MODULE = "/usr/lib/libcs_pkcs11_R3.so";
    public static HSMManager hsmManager;
    static String label = null;

    private static void printUsage() {
        System.out.println("Functions: ");
        System.out.println("\t 1.GetInstance");
        System.out.println("\t 2.SignHash");
        System.out.println("\t 3.GenECDSAKey");
        System.out.println("\t 4.genCSR_ECDSA");
        System.out.println("\t 5.FindPrivateKey");
        System.out.println("\t 6.genRSAKey");
        System.out.println("\t 7.genCSR_RSA");
        System.out.println("\t 8.signJWTByECDSA");
        System.out.println("\t 9.verifyJWTByECDSA");
        System.out.println("\t *.quit");

    }

    public static void main(String[] args) throws IOException, Exception {
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
                    getInstance();
                    break;
                case 2:
                    signHash();
                    break;
                case 3:
                    genECDSAKey();
                    break;
                case 4:
                    genCSR_ECDSA();
                    break;
                case 5:
                    findPrivateKey("uit_dsc_signer_test_4","RSA");
                    break;
                case 6:
                    genRSAKey(2048, "uit_dsc_signer_test_4");
                    break;
                case 7:
                    genCSR_RSA("uit_dsc_signer_test_4");
                    break;
                case 8:
                    signJWTByECDSA();
                    break;
                case 9:
                    verifyJWTByECDSA();
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

    static void getInstance() throws Exception {
        String sofile = "/usr/lib/libcs_pkcs11_R3.so";
        String wrapper = "/root/TestIAIK/libpkcs11wrapper.so";
//        String wrapper = "/usr/lib/libpkcs11wrapper.so";
        String slotstr = "0";
        String pin = "12345678";
        
        hsmManager = HSMManagerImp.getInstance(sofile, wrapper, Integer.parseInt(slotstr), pin);
    }

    static void signHash() throws Exception {
        byte[] hashBytes = "gw6Ah9L3wC55RRXtH5StN809mVypL6H3YPEASast110=".getBytes();
        String hashWrapped = "{\"KeyName\":\"qryptomid\",\"PrivateKey\":null,\"KeyAlg\":\"ECDSA\"}";
        byte[] hashWrappedData = Base64.getEncoder().encode(hashWrapped.getBytes());
        String aseKeyname = "qryptomid";

        for (int i = 0; i < 1000; i++) {
            byte[] s = hsmManager.signHash(hashBytes, hashWrappedData, aseKeyname);
            System.out.println("signature: " + i + ": " + Base64.getEncoder().encodeToString(s));
        }
    }

    private static void genECDSAKey() throws Exception {
        int length = 2;
        String keyLabel = "uit_dsc_signer_test_5";

        iaik.pkcs.pkcs11.objects.KeyPair kp = hsmManager.genECDSAKeyPair(length, keyLabel);
        if (kp != null) {
            label = keyLabel;
            System.out.println("Generate ECDSA key successfully with name = " + keyLabel);
        } else {
            System.out.println("Generate ECDSA key error");
        }

    }

    private static void genRSAKey(int size, String keyLabel) throws Exception {
//        int length = 2;
//        String keyLabel = "uit_dsc_signer_test_4";

        iaik.pkcs.pkcs11.objects.KeyPair kp = hsmManager.genRSAKeyPair(size, keyLabel);
        if (kp != null) {
            label = keyLabel;
            System.out.println("Generate RSA key successfully with name = " + keyLabel);
        } else {
            System.out.println("Generate ECDSA key error");
        }

    }

    private static void genCSR_ECDSA() throws Exception {
        String keyLabel = "uit_dsc_signer_test_3";
        StringBuilder builder = new StringBuilder();
        builder.append("UID=MST:123456789,");
        builder.append("CN=UIT DSC Signer TEST,");
        builder.append("O=UIT DSC Signer TEST,");
        builder.append("ST=Ho Chi Minh,");
        builder.append("C=VN");

        X500Name x500Name = new X500Name(builder.toString());
        String csr = hsmManager.gen_CSR(HSMManagerImp.KeyType.ECDSA, keyLabel, builder);
        System.out.println("stringBuilder: " + builder);
        System.out.println("x500Name: " + x500Name);
        System.out.println(csr);
    }

    private static void genCSR_RSA(String keyLabel) throws Exception {
//        String keyLabel = "uit_dsc_signer_test_4";
        StringBuilder builder = new StringBuilder();
        builder.append("UID=MST:123456789,");
        builder.append("CN=UIT DSC Signer TEST,");
        builder.append("O=UIT DSC Signer TEST,");
        builder.append("ST=Ho Chi Minh,");
        builder.append("C=VN");

        X500Name x500Name = new X500Name(builder.toString());
        String csr = hsmManager.gen_CSR(HSMManagerImp.KeyType.RSA, keyLabel, builder);
        System.out.println("stringBuilder: " + builder);
        System.out.println("x500Name: " + x500Name);
        System.out.println(csr);
    }

    private static void findPrivateKey(String labels, String keyType) throws Exception {
//        String labels = "uit_dsc_signer_test_3";

        if (labels != null) {
            switch (keyType) {
                case "RSA":
                    PrivateKey priKey = hsmManager.findPrivateKey(labels, "RSA");
                    System.out.println("RSAPrivateKey: " + priKey);
                    break;
                case "ECDSA":
                    ECDSAPrivateKey pk = hsmManager.findECDSAPrivateKey(labels);
                    System.out.println("ECDSAPrivateKey: " + pk);
                    break;
                default:
                    throw new AssertionError();
            }
        }

    }

    private static String getRandomKeyID() {
        String keyID = null;
        try {

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

    private static void signJWTByECDSA() throws Exception {
        String hashWrapped = "{\"KeyName\":\"qryptomid\",\"PrivateKey\":null,\"KeyAlg\":\"ECDSA\"}";
        byte[] hashWrappedData = Base64.getEncoder().encode(hashWrapped.getBytes());
        String aseKeyname = "qryptomid";
        
        UUID uuid = UUID.randomUUID();
        String keyLabel = uuid.toString();

        // Header
        Map<String, String> header = new HashMap<>();
        header.put("kid", keyLabel);
        header.put("typ", "JWT");
        header.put("alg", "ES256");

//         Convert header to JSON string
        ObjectMapper mapper = new ObjectMapper();
        String headerJson = mapper.writeValueAsString(header);
                
        // Payload
        String payload = "{\"sub\":\"did:sov:78104_NeCMvLOASwAeBB2VTgGN5UtGbD6I8yMlQ0ITCDSBNoQ\",\"nbf\":1714965400,\"iss\":\"QC1:MOBILEID:Tu5pnK47rL0=:MOBILE_ID\",\"exp\":1734757200,\"vc\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://qryptoservice.mobile-id.vn/credentials/v1\"],\"type\":[\"VerifiableCredential\",\"ABCDEF\"],\"credentialSubject\":{\"data\":{\"data\":{\"0467eb56-089e-45e6-8f2d-523e666304cd\":\"cccccc\"},\"ci\":\"QC1:MOBILEID:PAED7D7QJ561UVOYUK9R5A60E1\",\"format\":{\"fields\":[{\"File1\":{\"type\":\"t2\",\"kvalue\":\"0467eb56-089e-45e6-8f2d-523e666304cd\"}},{\"test f\":{\"type\":\"f1\",\"file_type\":\"application/pdf\",\"file_field\":\"a2766715-8c12-47f0-876d-76e8d21cb0f6\",\"file_token\":\"MWQzZjE4MzgtMjE1YS00NTMxLTgyNTItNWUxYzcyN2QyMjFl\",\"file_name\":\"CT TOUR_THÀNH ĐÔ-CTC-GẤU TRÚC MOBILE-ID 2024.pdf\",\"share_mode\":3}}],\"version\":\"2\"},\"title\":\"Demo Qrypto\"}}},\"jti\":\"QC1:MOBILEID:PAED7D7QJ561UVOYUK9R5A60E1\"}";
        
        jwt = hsmManager.signJWTByEDCSA(headerJson, payload, hashWrappedData, aseKeyname);
        
        System.out.println("SIGNATURE JWT: " + jwt);
    }
    
    private static void verifyJWTByECDSA() throws Exception {
        // Payload
        String payload = "{\"sub\":\"did:sov:78104_NeCMvLOASwAeBB2VTgGN5UtGbD6I8yMlQ0ITCDSBNoQ\",\"nbf\":1714965400,\"iss\":\"QC1:MOBILEID:Tu5pnK47rL0=:MOBILE_ID\",\"exp\":1734757200,\"vc\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://qryptoservice.mobile-id.vn/credentials/v1\"],\"type\":[\"VerifiableCredential\",\"ABCDEF\"],\"credentialSubject\":{\"data\":{\"data\":{\"0467eb56-089e-45e6-8f2d-523e666304cd\":\"cccccc\"},\"ci\":\"QC1:MOBILEID:PAED7D7QJ561UVOYUK9R5A60E1\",\"format\":{\"fields\":[{\"File1\":{\"type\":\"t2\",\"kvalue\":\"0467eb56-089e-45e6-8f2d-523e666304cd\"}},{\"test f\":{\"type\":\"f1\",\"file_type\":\"application/pdf\",\"file_field\":\"a2766715-8c12-47f0-876d-76e8d21cb0f6\",\"file_token\":\"MWQzZjE4MzgtMjE1YS00NTMxLTgyNTItNWUxYzcyN2QyMjFl\",\"file_name\":\"CT TOUR_THÀNH ĐÔ-CTC-GẤU TRÚC MOBILE-ID 2024.pdf\",\"share_mode\":3}}],\"version\":\"2\"},\"title\":\"Demo Qrypto\"}}},\"jti\":\"QC1:MOBILEID:PAED7D7QJ561UVOYUK9R5A60E1\"}";
        
        String hashWrapped = "{\"KeyName\":\"qryptomid\",\"PrivateKey\":null,\"KeyAlg\":\"ECDSA\"}";
        byte[] hashWrappedData = Base64.getEncoder().encode(hashWrapped.getBytes());
        String aseKeyname = "qryptomid";
        
        System.out.println("LINE 250: TestIAIK_Sesion.java -- jwt.euals: " + (jwt.equals("")));
        System.out.println("VERIFY SIGNATURE JWT: " + hsmManager.verifiedJWTByEDCSA(jwt, hashWrappedData, aseKeyname));
    }
}
