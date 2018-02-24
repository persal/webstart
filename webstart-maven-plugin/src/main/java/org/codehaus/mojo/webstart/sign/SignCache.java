package org.codehaus.mojo.webstart.sign;

import org.codehaus.mojo.webstart.util.DefaultIOUtil;
import org.codehaus.mojo.webstart.util.IOUtil;
import org.codehaus.plexus.logging.Logger;
import org.codehaus.plexus.logging.console.ConsoleLogger;

import java.io.Closeable;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;

public class SignCache {

    private static final String DIGEST_ALGO = "SHA-1";
    private static final String PROPERTY_SIGNCACHE_DIR = "signcache.dir";
    private static final String PROPERTY_USER_HOME = "user.home";
    private static final String DEFAULT_SIGNCACHE_DIR = ".m2/signcache";
    private static final String SYSTEM_PROPERTY_SIGNCACHE = "signcache"; //ex: -Dsigncache=false
    private static final int MAX_CACHE_SAME_DIR = 20;

    Logger logger = new ConsoleLogger(Logger.LEVEL_INFO, "signcache");

    private boolean activated = true;
    private File cacheBasedir;
    private static String processUnique;

    private Map<String, String> manifest = new LinkedHashMap<>();
    private final IOUtil ioUtil = new DefaultIOUtil();
    private static final SignCache instance = new SignCache();
    private String signature = null;

    public SignCache() {
        String customCacheBasedir = System.getProperty(PROPERTY_SIGNCACHE_DIR);
        if (customCacheBasedir != null) {
            cacheBasedir = new File(customCacheBasedir);
        } else {
            String userHome = System.getProperty(PROPERTY_USER_HOME);
            cacheBasedir = new File(userHome, DEFAULT_SIGNCACHE_DIR);
        }

        processUnique = UUID.randomUUID().toString().replaceAll("-", "");

        activated = "true".equals(System.getProperty(SYSTEM_PROPERTY_SIGNCACHE, "true"));
        logger.info("Use signcache: " + activated);
        logger.info("Hash algo: " + DIGEST_ALGO);
    }

    public static SignCache instance() {
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
        if (signature == null) {
            try {
                File dummyJar = SignCache.instance().createDummyJar();
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
        logger.info("Cache hit: " + cacheFile.exists() + "  " + cacheFile.getAbsoluteFile());
        return cacheFile.exists();
    }

    private File resolveCacheDir(String jarName) {
        String subdir = jarName.toLowerCase()
                .replaceAll("snapshot", "")
                .replaceAll("final", "")
                .replaceAll("release", "")
                .replaceAll("\\.jar$", "")
                .replaceAll("[^a-z]*", "");
        return new File(new File(cacheBasedir, signature), subdir);
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
        purgeCache(cacheDir);
    }

    private void purgeCache(File cacheDir) {
        File[] cacheFiles = cacheDir.listFiles(new FileFilter() {
            @Override
            public boolean accept(File pathname) {
                return !pathname.isDirectory();
            }
        });

        if (cacheFiles.length > MAX_CACHE_SAME_DIR) {
            Arrays.sort(cacheFiles, new Comparator<File>() {
                @Override
                public int compare(File o1, File o2) {
                    return Long.valueOf(o1.lastModified()).compareTo(o2.lastModified());
                }
            });
            for (int i = 0; i < cacheFiles.length - MAX_CACHE_SAME_DIR; i++) {
                logger.info("Purge cache: " + cacheFiles[i].getName() + " " + new Date((cacheFiles[i].lastModified())));
                try {
                    if (!cacheFiles[i].delete()) {
                        logger.warn("Unable to delete file " + cacheFiles[i].getAbsolutePath());
                    }
                } catch (Exception e) {
                    logger.warn("Unable to purge snapshots", e);
                }
            }
        }
    }

    public void copy(File sourceFile, File targetFile) {
        File tmpFile = new File(cacheBasedir, "tmp_" + targetFile.getName() + "_" + processUnique);
        logger.info("Tmp file: " + tmpFile.getAbsoluteFile());
        try {
            ioUtil.copyFile(sourceFile, tmpFile);
            ioUtil.renameTo(tmpFile, targetFile); //atomic
        } catch (Exception e) {
            logger.warn("Unable to cache " + targetFile + ", ", e);
        } finally {
            if (tmpFile.exists()) {
                try {
                    tmpFile.delete();
                } catch (Exception e) {
                    logger.warn("Unable to delete tmp file: " + tmpFile.getAbsolutePath(), e);
                }
            }
        }
    }
}
