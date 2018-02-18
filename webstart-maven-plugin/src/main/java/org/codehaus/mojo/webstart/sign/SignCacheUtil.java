package org.codehaus.mojo.webstart.sign;

import org.apache.commons.lang.RandomStringUtils;
import org.codehaus.mojo.webstart.util.DefaultIOUtil;
import org.codehaus.mojo.webstart.util.IOUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

public class SignCacheUtil {

    private boolean activated = true;
    private File cacheBasedir;
    private static String unique;

    private Map<String, String> manifest = new LinkedHashMap<>();
    private final IOUtil ioUtil = new DefaultIOUtil();
    private static final SignCacheUtil instance = new SignCacheUtil();

    public SignCacheUtil() {
        String customCacheBasedir = System.getProperty("signcache.dir");
        if (customCacheBasedir != null) {
            cacheBasedir = new File(customCacheBasedir);
        } else {
            String userHome = System.getProperty("user.home");
            cacheBasedir = new File(userHome, ".m2/signcache");
        }

        //unique = UUID.randomUUID().toString().replaceAll("-", "");
        unique = RandomStringUtils.random(12, true, true);

        activated = "true".equals(System.getProperty("signcache", "true"));
        System.out.println("Use signcache: " + activated);
    }

    public static SignCacheUtil instance() {
        return instance;
    }

    public String hashOf(File file) {
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            MessageDigest digest = MessageDigest.getInstance("SHA1");
            byte[] block = new byte[4096];
            int length;
            while ((length = in.read(block)) > 0) {
                digest.update(block, 0, length);
            }
            return String.format("%032X", new BigInteger(1, digest.digest()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            try {
                in.close();
            } catch (IOException e) {
                //empty
            }
        }
    }

    public boolean isCached(File unsignedJarFile, String jarName) {
        if (jarName.startsWith("unprocessed_")) {
            jarName = jarName.substring(12);
        }
        File cacheFile = new File(resolveCacheDir(jarName), jarName + "_" + hashOf(unsignedJarFile));
        System.out.println("isCached: " + cacheFile.exists() + "  " + cacheFile.getAbsoluteFile());
        return cacheFile.exists();
    }

    private File resolveCacheDir(String jarName) {
        String snapSuffix = "-snapshot.jar";
        if (jarName.toLowerCase().endsWith(snapSuffix)) {
            jarName = jarName.substring(0, jarName.length() - snapSuffix.length());
        }
        int index = jarName.lastIndexOf('-');
        if (index != -1) {
            String subdir = jarName.substring(0, index).toLowerCase();
            return new File(cacheBasedir, subdir);
        } else {
            return cacheBasedir;
        }
    }

    public void replaceWithSignedCache(File unsignedJarFile, File targetJarFile) {
        String jarName = targetJarFile.getName();
        File cachedFile = new File(resolveCacheDir(jarName), jarName + "_" + hashOf(unsignedJarFile));

        try {
            ioUtil.copyFile(cachedFile, targetJarFile);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean isActivated() {
        return activated;
    }

    public Map<String, String> getManifest() {
        return manifest;
    }

    public void setManifest(Map<String, String> manifest) {
        this.manifest = manifest;
    }

    public boolean isCachable(File file) {
        return !file.getName().contains("-SNAPSHOT");
    }

    public void cacheSignedFile(String hash, File signedJarFile) {
        String jarName = signedJarFile.getName();
        File cacheDir = resolveCacheDir(jarName);
        if (!cacheDir.exists() && !cacheDir.mkdirs()) {
            throw new RuntimeException("Unable to create dir " + cacheDir.getAbsolutePath());
        }

        File cacheFile = new File(cacheDir, jarName + "_" + hash);
        copy(signedJarFile, cacheFile);
    }

    public void copy(File sourceFile, File targetFile) {
        File tmpFile = new File(targetFile.getParent(), "tmp_" + targetFile.getName() + "_" + unique);
        System.out.println("Tmp file: " + tmpFile.getAbsoluteFile());
        try {
            ioUtil.copyFile(sourceFile, tmpFile);
            ioUtil.renameTo(tmpFile, targetFile); //atomic
        } catch (Exception e) {
            System.err.println("WARN Unable to cache " + targetFile + ", " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (tmpFile.exists()) {
                try {
                    tmpFile.delete();
                } catch (Exception e) {
                    System.err.println("WARN Unable to delete tmp file: " + tmpFile.getAbsolutePath());
                }
            }
        }
    }
}
