package main;

import java.io.File;
import java.io.FileOutputStream;
import java.util.concurrent.CountDownLatch;

import org.apache.hadoop.yarn.conf.YarnConfiguration;
import org.apache.hadoop.yarn.server.MiniYARNCluster;

public class Main {

    public static void main(String args[]) throws Exception {
        new File("target/test").mkdirs();

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

        System.out.println("Ready!");

        // SIGTERM triggers the JVM shutdown hook above, which stops the cluster.
        new CountDownLatch(1).await();
    }
}
