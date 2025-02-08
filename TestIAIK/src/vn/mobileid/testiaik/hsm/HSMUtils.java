/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vn.mobileid.testiaik.hsm;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import vn.mobileid.testiaik.utils.Utils;

/**
 *
 * @author ADMIN
 */
public class HSMUtils {
    
    final private static Logger LOG = LogManager.getLogger(HSMUtils.class);

    private static final String PATH32 = "wrapper32/";
    private static final String PATH64 = "wrapper64/";

    private static String OS = System.getProperty("os.name").toLowerCase();

    public static String loadP11Wrapper() throws IOException {
        String fileName = "pkcs11wrapper.dll";
        if (isWindows()) {
            fileName = "pkcs11wrapper.dll";
        } else if (isUnix()) {
            fileName = "libpkcs11wrapper.so";
        } else {
            throw new IOException("Cannot get PKCS#11 Wrapper due to unsupported OS.");
        }
        String resourceName;
        if (System.getProperty("sun.arch.data.model").compareTo("32") == 0) {
            resourceName = PATH32 + fileName;
        } else {
            resourceName = PATH64 + fileName;
        }

        boolean useSeperator = false;
        if (System.getProperty("java.io.tmpdir").charAt(System.getProperty("java.io.tmpdir").length() - 1) == File.separatorChar) {
            useSeperator = false;
        } else {
            useSeperator = true;
        }

        String fullPathOfWrapper = System.getProperty("java.io.tmpdir") + (useSeperator == true ? File.separator : "") + fileName;
        LOG.debug("Warpper path: " + fullPathOfWrapper);
        File f = new File(fullPathOfWrapper);
        if (f.exists()) {
            return f.getAbsolutePath();
        } else {
            InputStream in = HSMUtils.class.getClassLoader().getResourceAsStream(resourceName);
            try (OutputStream os = new FileOutputStream(f)) {
                IOUtils.write(Utils.saveByteArrayOutputStream(in), os);
            }
            return f.getAbsolutePath();
        }
    }

    public static boolean isWindows() {

        return (OS.indexOf("win") >= 0);

    }

    public static boolean isMac() {

        return (OS.indexOf("mac") >= 0);

    }

    public static boolean isUnix() {

        return (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0);

    }

    public static boolean isSolaris() {

        return (OS.indexOf("sunos") >= 0);
    }
}
