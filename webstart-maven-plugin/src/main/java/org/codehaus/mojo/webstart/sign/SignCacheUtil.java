package org.codehaus.mojo.webstart.sign;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;

import org.codehaus.mojo.webstart.util.DefaultIOUtil;
import org.codehaus.mojo.webstart.util.IOUtil;

public class SignCacheUtil {

    private static final String DIGEST_ALGO = "SHA-1";
    private static final String PROPERTY_SIGNCACHE_DIR = "signcache.dir";
    private static final String PROPERTY_USER_HOME = "user.home";
    private static final String DEFAULT_SIGNCACHE_DIR = ".m2/signcache";
    private static final String SYSTEM_PROPERTY_SIGNCACHE = "signcache"; //ex: -Dsigncache=false

    private boolean activated = true;
    private File cacheBasedir;
    private static String unique;

    private Map<String, String> manifest = new LinkedHashMap<>();
    private final IOUtil ioUtil = new DefaultIOUtil();
    private static final SignCacheUtil instance = new SignCacheUtil();
    private String signature = null;

    public SignCacheUtil() {
        String customCacheBasedir = System.getProperty(PROPERTY_SIGNCACHE_DIR);
        if (customCacheBasedir != null) {
            cacheBasedir = new File(customCacheBasedir);
        } else {
            String userHome = System.getProperty(PROPERTY_USER_HOME);
            cacheBasedir = new File(userHome, DEFAULT_SIGNCACHE_DIR);
        }

        unique = UUID.randomUUID().toString().replaceAll("-", "");
        //unique = RandomStringUtils.random(12, true, true);

        activated = "true".equals(System.getProperty(SYSTEM_PROPERTY_SIGNCACHE, "true"));
        System.out.println("Use signcache: " + activated);
        System.out.println("Hash algo: " + DIGEST_ALGO);
    }

    public static SignCacheUtil instance() {
        return instance;
    }

    public String hashOf(File file) {
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGO);
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

    public void closeSilent(Closeable c) {
        try {
            c.close();
        } catch (Exception e) {
            //empty
        }
    }

    public void updateSignature(SignConfig config, DefaultSignTool signTool) {
        if(signature == null) {
            try {
                File dummyJar = SignCacheUtil.instance().createDummyJar();
                dummyJar.deleteOnExit();
                signTool.signNonCached(config, dummyJar, null);

                String alias = config.getAlias().toUpperCase();
                if (alias.length() > 8) {
                    alias = alias.substring(0, 8);
                }

                JarFile jar = new JarFile(dummyJar);
                ZipEntry entry = jar.getEntry("META-INF/" + alias + ".SF");
                InputStream inputStream = jar.getInputStream(entry);
                Manifest mf = new Manifest();
                mf.read(inputStream);
                signature = mf.getMainAttributes().getValue("SHA-256-Digest-Manifest");
                signature = alias.toLowerCase() + "_" + signature.substring(0, 8);
                dummyJar.delete();
            } catch (Exception e) {
                throw new RuntimeException("Unable to determine SHA-256-Digest-Manifest from .SF file", e);
            }
        }
    }

    public File createDummyJar() {
        FileOutputStream stream = null;
        JarOutputStream out = null;
        try {
            File f = File.createTempFile("sign", "jar");
            f.deleteOnExit();
            stream = new FileOutputStream(f);
            out = new JarOutputStream(stream, new Manifest());
            return f;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        } finally {
            closeSilent(out);
            closeSilent(stream);
        }
    }

    public String hash(byte[] text) {
        try {
            MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGO);
            byte[] hash = digest.digest(text);
            return String.format("%032X", new BigInteger(1, hash));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
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
            return new File(new File(cacheBasedir, signature), subdir);
        } else {
            return new File(cacheBasedir, signature);
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
        File tmpFile = new File(cacheBasedir, "tmp_" + targetFile.getName() + "_" + unique);
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
