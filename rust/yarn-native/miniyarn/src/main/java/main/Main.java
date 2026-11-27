package main;

import java.io.File;
import java.io.FileOutputStream;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import org.apache.hadoop.yarn.conf.YarnConfiguration;
import org.apache.hadoop.yarn.server.MiniYARNCluster;

public class Main {

    // Tests ask for a ResourceManager restart by creating this file, and wait for the done file.
    private static final File RESTART_TRIGGER = new File("target/test/restart-rm");
    private static final File RESTART_DONE = new File("target/test/rm-restarted");

    public static void main(String args[]) throws Exception {
        Set<String> flags = new HashSet<>();
        for (String arg : args) {
            flags.add(arg);
        }

        new File("target/test").mkdirs();
        RESTART_TRIGGER.delete();
        RESTART_DONE.delete();

        YarnConfiguration conf = new YarnConfiguration();
        // Small containers so tests fit on any machine
        conf.setInt(YarnConfiguration.RM_SCHEDULER_MINIMUM_ALLOCATION_MB, 64);
        conf.setInt(YarnConfiguration.NM_PMEM_MB, 4096);
        conf.setBoolean(YarnConfiguration.NM_PMEM_CHECK_ENABLED, false);
        conf.setBoolean(YarnConfiguration.NM_VMEM_CHECK_ENABLED, false);
        // Don't mark the node unhealthy when the test machine's disk is nearly full
        conf.setFloat(
            YarnConfiguration.NM_MAX_PER_DISK_UTILIZATION_PERCENTAGE, 100.0f);
        // Fail fast so tests don't wait for retries of an attempt
        conf.setInt(YarnConfiguration.RM_AM_MAX_ATTEMPTS, 1);

        if (flags.contains("recovery")) {
            // Keep application state on disk so a restarted ResourceManager recovers it, and
            // keep containers running across the restart
            File stateStore = new File("target/test/rm-state-store").getAbsoluteFile();
            deleteRecursively(stateStore);
            conf.setBoolean(YarnConfiguration.RECOVERY_ENABLED, true);
            conf.setBoolean(YarnConfiguration.RM_WORK_PRESERVING_RECOVERY_ENABLED, true);
            conf.set(YarnConfiguration.RM_STORE,
                "org.apache.hadoop.yarn.server.resourcemanager.recovery.FileSystemRMStateStore");
            conf.set(YarnConfiguration.FS_RM_STATE_STORE_URI, stateStore.toURI().toString());
            // Reconnect quickly once the restarted ResourceManager is up, instead of after the
            // default 30 second retry interval
            conf.setLong(YarnConfiguration.RESOURCEMANAGER_CONNECT_RETRY_INTERVAL_MS, 500);
            conf.setLong(YarnConfiguration.NM_RESOURCEMANAGER_CONNECT_RETRY_INTERVAL_MS, 500);
            // By default the NodeManager calls the ResourceManager in-process, so it would keep
            // talking to the stopped instance. Over RPC it reconnects, which needs fixed ports.
            conf.setBoolean(YarnConfiguration.YARN_MINICLUSTER_USE_RPC, true);
            conf.setBoolean(YarnConfiguration.YARN_MINICLUSTER_FIXED_PORTS, true);
            conf.set(YarnConfiguration.RM_ADDRESS, "localhost:18032");
            conf.set(YarnConfiguration.RM_SCHEDULER_ADDRESS, "localhost:18030");
            conf.set(YarnConfiguration.RM_RESOURCE_TRACKER_ADDRESS, "localhost:18031");
            conf.set(YarnConfiguration.RM_ADMIN_ADDRESS, "localhost:18033");
            conf.set(YarnConfiguration.RM_WEBAPP_ADDRESS, "localhost:18088");
        }

        MiniYARNCluster yarn = new MiniYARNCluster("yarn-native", 1, 1, 1);
        yarn.init(conf);
        yarn.start();
        if (!yarn.waitForNodeManagersToConnect(60_000)) {
            throw new IllegalStateException("NodeManager did not register with the ResourceManager");
        }

        // The cluster's config holds the ports it bound
        yarn.getConfig().writeXml(new FileOutputStream("target/test/yarn-site.xml"));

        final MiniYARNCluster shutdownYarn = yarn;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                shutdownYarn.stop();
            } catch (Exception e) {
                e.printStackTrace(System.err);
            }
        }, "miniyarn-shutdown"));

        if (flags.contains("recovery")) {
            Thread restarter = new Thread(() -> watchForRestarts(shutdownYarn), "miniyarn-restarter");
            restarter.setDaemon(true);
            restarter.start();
        }

        System.out.println("Ready!");

        // SIGTERM triggers the JVM shutdown hook above, which stops the cluster.
        new CountDownLatch(1).await();
    }

    private static void watchForRestarts(MiniYARNCluster yarn) {
        while (true) {
            try {
                if (RESTART_TRIGGER.delete()) {
                    yarn.restartResourceManager(0);
                    if (!yarn.waitForNodeManagersToConnect(60_000)) {
                        throw new IllegalStateException("NodeManager did not re-register");
                    }
                    RESTART_DONE.createNewFile();
                }
                Thread.sleep(100);
            } catch (Exception e) {
                e.printStackTrace(System.err);
                return;
            }
        }
    }

    private static void deleteRecursively(File file) {
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteRecursively(child);
            }
        }
        file.delete();
    }
}
