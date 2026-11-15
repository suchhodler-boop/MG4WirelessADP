// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 MG4 Wireless ADB contributors
// Distributed without warranty; see LICENSE.
// MG4 enable sequence derived from ADBUtil, Copyright (c) 2026 Leon Kernan.
// Upstream MIT notice: LICENSE-ADBUtil.
package com.mg4.hardwareprobe;

import android.content.Context;
import android.os.Process;
import android.provider.Settings;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

/** MG4-specific privileged ADB enable sequence derived from lkernan/ADBUtil. */
final class AdbEnableWorkflow {
    private final Context context;
    private final StringBuilder log = new StringBuilder(5000);

    AdbEnableWorkflow(Context context) { this.context = context; }

    Result run(int port) {
        line("MG4 PRIVILEGED ADB ENABLE + WIRELESS SETUP");
        line("Generated: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.US).format(new Date()));
        line("Process UID: " + Process.myUid());
        if (Process.myUid() != Process.SYSTEM_UID) {
            return fail("This build is not running as Android system UID 1000", port);
        }

        try {
            boolean changed = Settings.Global.putInt(context.getContentResolver(), Settings.Global.ADB_ENABLED, 1);
            line("Settings.Global.adb_enabled=1: " + (changed ? "applied" : "provider returned false"));
            pause(500);
            setprop("persist.sys.service.otg_gadget", "1");
            pause(500);
            setprop("allgo.usb.interface", "up");
            pause(500);
            setprop("sys.usb.config", "none");
            pause(500);
            setprop("sys.usb.config", "mass_storage,adb");
            pause(500);
            setprop("ctl.restart", "adbd");
        } catch (Exception e) {
            line("ERROR: " + e.getClass().getSimpleName() + ": " + safe(e.getMessage()));
            return fail("ADB enable sequence failed", port);
        }

        line("Stage 1 verification: waiting for adbd on localhost");
        int openPort = waitForEitherPort(5555, port, 20000);
        line("Detected ADB port: " + (openPort == 0 ? "NONE" : String.valueOf(openPort)));
        String instructions = connectionText(port);
        if (openPort == 0) {
            return new Result(false, "ADB enable properties applied, but adbd did not open port 5555 or " + port,
                    log.toString(), instructions);
        }
        if (openPort != port) {
            line("");
            line("Stage 2: authenticated self-ADB switch from " + openPort + " to " + port);
            AdbPortSwitcher.Result switched = new AdbPortSwitcher(context).switchPort(openPort, port);
            log.append('\n').append(switched.log);
            if (!switched.success) {
                return new Result(false, "ADB was enabled on " + openPort + ", but the switch to " + port + " failed: " + switched.summary,
                        log.toString(), instructions);
            }
        }
        line("RESULT: SUCCESS");
        return new Result(true, "ADB enabled and listening on " + port, log.toString(), instructions);
    }

    private void setprop(String key, String value) throws Exception {
        java.lang.Process process = new ProcessBuilder("setprop", key, value).start();
        int exit = process.waitFor();
        if (exit != 0) throw new IllegalStateException("setprop " + key + " failed with exit " + exit);
        line("setprop " + key + " " + value + ": applied");
    }

    private String connectionText(int port) {
        List<String> ipv4 = new ArrayList<String>();
        List<String> ipv6 = new ArrayList<String>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface network = interfaces.nextElement();
                if (!network.isUp() || network.isLoopback()) continue;
                Enumeration<InetAddress> addresses = network.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();
                    if (address.isLoopbackAddress() || address.isLinkLocalAddress()) continue;
                    String host = address.getHostAddress();
                    int scope = host.indexOf('%');
                    if (scope >= 0) host = host.substring(0, scope);
                    String item = network.getName() + " = " + host;
                    if (address instanceof Inet6Address) ipv6.add(item); else ipv4.add(item);
                }
            }
        } catch (Exception e) {
            line("Address enumeration warning: " + safe(e.getMessage()));
        }

        StringBuilder text = new StringBuilder(2000);
        text.append("MG4 WIRELESS ADB CONNECTION\n");
        text.append("Generated: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.US).format(new Date())).append("\n");
        text.append("Port: ").append(port).append("\n\nIPv4 addresses:\n");
        for (String address : ipv4) text.append("  ").append(address).append('\n');
        if (ipv4.isEmpty()) text.append("  none found\n");
        text.append("\nGlobal IPv6 addresses:\n");
        for (String address : ipv6) text.append("  ").append(address).append('\n');
        if (ipv6.isEmpty()) text.append("  none found\n");
        text.append("\nCOMMANDS\n");
        for (String address : ipv4) appendCommands(text, address, port, false);
        for (String address : ipv6) appendCommands(text, address, port, true);
        text.append("\nUse Android SDK Platform-Tools ADB 1.0.41. IPv6 addresses require square brackets.\n");
        text.append("If IPv4 is blocked by the vehicle firewall/network, use the global IPv6 address.\n");
        return text.toString();
    }

    private static void appendCommands(StringBuilder text, String address, int port, boolean brackets) {
        String host = address.substring(address.indexOf(" = ") + 3);
        String target = brackets ? "[" + host + "]:" + port : host + ":" + port;
        text.append("adb connect ").append(target).append('\n');
        text.append("adb -s ").append(target).append(" shell\n");
    }

    private boolean waitForPort(int port, long maximumMillis) {
        long end = System.currentTimeMillis() + maximumMillis;
        while (System.currentTimeMillis() < end) {
            Socket socket = new Socket();
            try {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 700);
                return true;
            } catch (Exception ignored) {
                pause(400);
            } finally {
                try { socket.close(); } catch (Exception ignored) { }
            }
        }
        return false;
    }

    private int waitForEitherPort(int first, int second, long maximumMillis) {
        long end = System.currentTimeMillis() + maximumMillis;
        while (System.currentTimeMillis() < end) {
            if (canConnect(first)) return first;
            if (second != first && canConnect(second)) return second;
            pause(400);
        }
        return 0;
    }

    private boolean canConnect(int port) {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 600);
            return true;
        } catch (Exception ignored) {
            return false;
        } finally {
            try { socket.close(); } catch (Exception ignored) { }
        }
    }

    private Result fail(String summary, int port) {
        line("RESULT: NOT COMPLETED: " + summary);
        return new Result(false, summary, log.toString(), connectionText(port));
    }

    private void line(String text) { log.append(text).append('\n'); }
    private static String safe(String value) { return value == null ? "" : value; }
    private static void pause(long millis) {
        try { Thread.sleep(millis); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    static final class Result {
        final boolean success;
        final String summary;
        final String log;
        final String connectionText;
        Result(boolean success, String summary, String log, String connectionText) {
            this.success = success;
            this.summary = summary;
            this.log = log;
            this.connectionText = connectionText;
        }
    }
}
