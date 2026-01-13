package com.github.smartdns;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public class SmartDnsManager {
    private static final Pattern COMMA_SEPARATOR = Pattern.compile("\\s*,\\s*");
    private static final SmartDnsManager INSTANCE = new SmartDnsManager();
    private volatile boolean started = false;

    public static void loadDnsCacheConfig() {
        String dcmConfigFileName = System.getProperty("dcm.config.filename", "dns-cache.properties");
        loadDnsCacheConfig(dcmConfigFileName);
    }

    public static void loadDnsCacheConfig(String propertiesFileName) {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(propertiesFileName);
        if (inputStream == null) {
            // 使用系统类加载器作为备选，避免getClassLoader()返回null的情况
            ClassLoader systemClassLoader = ClassLoader.getSystemClassLoader();
            if (systemClassLoader != null) {
                inputStream = systemClassLoader.getResourceAsStream(propertiesFileName);
            }
        }

        if (inputStream == null) {
            throw new UnsupportedOperationException("Fail to find " + propertiesFileName + " on classpath!");
        } else {
            try (InputStream autoCloseInputStream = inputStream) {
                Properties properties = new Properties();
                properties.load(autoCloseInputStream);

                for (Map.Entry<Object, Object> entry : properties.entrySet()) {
                    String host = (String) entry.getKey();
                    String ipList = (String) entry.getValue();
                    ipList = ipList.trim();
                    if (!ipList.isEmpty()) {
                        String[] ipsAndPort = ipList.split(":");
                        if (ipsAndPort.length == 1) {
                            INSTANCE.register(host, new ArrayList<>(Arrays.asList(COMMA_SEPARATOR.split(ipsAndPort[0]))), 0);
                        } else if (ipsAndPort.length == 2) { // 添加else if避免重复执行
                            int port;
                            try {
                                port = Integer.parseInt(ipsAndPort[1]);
                            } catch (NumberFormatException e) {
                                throw new UnsupportedOperationException("Invalid port number: " + ipsAndPort[1], e);
                            }
                            INSTANCE.register(host, new ArrayList<>(Arrays.asList(COMMA_SEPARATOR.split(ipsAndPort[0]))), port);
                        }
                    }
                }
                // 只启动一次调度器
                if (!INSTANCE.started) {
                    synchronized (INSTANCE) {
                        if (!INSTANCE.started) {
                            INSTANCE.start(100, TimeUnit.MILLISECONDS);
                            INSTANCE.started = true;
                        }
                    }
                }
            } catch (Exception e) {
                String message = String.format("Fail to loadDnsCacheConfig from %s, cause: %s", propertiesFileName, e);
                throw new UnsupportedOperationException(message, e);
            }
        }
    }

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "SmartDns-Monitor");
        t.setDaemon(true);
        return t;
    });

    private final Map<String, DomainConfig> managedDomains = new ConcurrentHashMap<>();

    private static class DomainConfig {
        String host;
        List<String> allIps;
        Integer port; // ports to probe

        // State - 使用线程安全的CopyOnWriteArrayList
        volatile List<String> currentHealthyIps = new ArrayList<>();

        DomainConfig(String host, List<String> allIps, Integer port) {
            this.host = host;
            this.allIps = allIps;
            this.port = port;
        }
    }

    /**
     * Register a domain for smart management.
     *
     * @param host Domain name (e.g. www.example.com)
     * @param ips  List of candidate IPs
     * @param port Ports to probe (default 80, 443 if empty)
     */
    public void register(String host, List<String> ips, int port) {
        managedDomains.put(host, new DomainConfig(host, ips, port));
    }

    /**
     * Start the monitoring loop.
     *
     * @param period Period between checks
     * @param unit   Time unit
     */
    public void start(long period, TimeUnit unit) {
        scheduler.scheduleAtFixedRate(this::checkHealthy, 0, period, unit);
    }

    /**
     * Stop the monitoring.
     */
    public void stop() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(1, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt(); // 恢复中断状态
        }
    }

    private void checkHealthy() {
        for (DomainConfig config : managedDomains.values()) {
            List<String> healthy = new ArrayList<>();
            for (String ip : config.allIps) {
                if (isHealthy(ip, config.port)) {
                    healthy.add(ip);
                }
            }

            // Check if changed
            if (!healthy.equals(config.currentHealthyIps) || healthy.isEmpty()) {
                config.currentHealthyIps = new ArrayList<>(healthy); // 创建新的列表副本
                if (healthy.isEmpty()) {
                    // If no IPs are healthy, remove from cache to allow fallback (or failure)
                    //DnsCacheManipulator.removeDnsCache(config.host);
                    DnsCacheManipulator.setDnsCache(config.host, "0.0.0.0");
                } else {
                    System.out.println("[SmartDns] Domain " + config.host + " healthy IPs: " + healthy);
                    DnsCacheManipulator.setDnsCache(config.host, healthy.toArray(new String[0]));
                }
            }
        }
    }

    protected boolean isHealthy(String ip, Integer port) {
        // 不配置端口，则不用探测
        if(Objects.isNull(port) || port <= 0) {
            return true;
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), 1000); // 1s timeout
        } catch (IOException e) {
            return false;
        }
        return true;
    }
}
