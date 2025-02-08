/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vn.mobileid.testiaik.utils;

import com.google.gson.Gson;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
import java.util.Random;
import java.util.TimeZone;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author ADMIN
 */
public class Utils {

    private static final Logger LOG = LogManager.getLogger(Utils.class);

    private static Gson gson = new Gson();

    public static boolean isNullOrEmpty(String value) {
        if (value == null) {
            return true;
        }
        if (value.compareTo("") == 0) {
            return true;
        }
        return false;
    }

    public static boolean isNullOrEmpty(List object) {
        if (object == null) {
            return true;
        }
        if (object.isEmpty()) {
            return true;
        }
        return false;
    }

    public static String getPropertiesFile(String fileName) {
        File folder = new File(System.getProperty("jboss.server.base.dir"));
        File[] listOfFiles = folder.listFiles();
        int i;
        for (i = 0; i < listOfFiles.length; i++) {
            if (listOfFiles[i].isFile()) {
                String filePath = listOfFiles[i].getAbsolutePath();
                if (filePath.contains(fileName)) {
                    return filePath;
                }
            }
        }
        return null;
    }

    public static String printStackTrace(Exception e) {
        String result = null;
        try {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            result = sw.toString();
            pw.close();
            sw.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return result;
    }

    public static String generateTransactionId() {
        String billCode = null;
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss");
            sdf.setTimeZone(TimeZone.getTimeZone(System.getProperty("user.timezone")));
            String dateTime = sdf.format(Calendar.getInstance().getTime());
            billCode = dateTime + "-" + generateOneTimePassword(6);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return billCode;
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

    public static String generateUUID() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString();
    }

    public static byte[] saveByteArrayOutputStream(InputStream body) {
        int c;
        byte[] r = null;
        try {
            ByteArrayOutputStream f = new ByteArrayOutputStream();
            while ((c = body.read()) > -1) {
                f.write(c);
            }
            r = f.toByteArray();
            f.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return r;
    }

    public static String toJson(Object o) {
        return gson.toJson(o);
    }

    public static byte[] genRandomArray(int size) throws NoSuchAlgorithmException, NoSuchProviderException {
        // TODO Auto-generated method stub
        byte[] random = new byte[size];
        new Random().nextBytes(random);
        return random;
    }
}
