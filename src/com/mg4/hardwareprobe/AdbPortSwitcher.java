// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 MG4 Wireless ADB contributors
// Distributed without warranty; see LICENSE.
package com.mg4.hardwareprobe;

import android.content.Context;
import android.util.Base64;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

import javax.crypto.Cipher;

/** Minimal ADB host transport for one authenticated tcpip:&lt;port&gt; request. */
final class AdbPortSwitcher {
    private static final int A_SYNC = command("SYNC");
    private static final int A_CNXN = command("CNXN");
    private static final int A_OPEN = command("OPEN");
    private static final int A_OKAY = command("OKAY");
    private static final int A_CLSE = command("CLSE");
    private static final int A_WRTE = command("WRTE");
    private static final int A_AUTH = command("AUTH");
    private static final int AUTH_TOKEN = 1;
    private static final int AUTH_SIGNATURE = 2;
    private static final int AUTH_PUBLIC_KEY = 3;
    private static final int VERSION = 0x01000000;
    private static final int MAX_DATA = 4096;
    private static final byte[] SHA1_DIGEST_INFO_PREFIX = hex("3021300906052b0e03021a05000414");

    private final Context context;
    private final StringBuilder log = new StringBuilder(8000);

    AdbPortSwitcher(Context context) { this.context = context; }

    Result switchPort(int sourcePort, int targetPort) {
        timestamp("MG4 SELF-ADB PORT SWITCH");
        line("Requested", "127.0.0.1:" + sourcePort + " -> TCP port " + targetPort);
        line("Security model", "Normal ADB RSA authorization; no root, remount, SELinux, or firewall changes");
        listAddresses();
        if (sourcePort == targetPort || sourcePort < 1 || targetPort < 1 || targetPort > 65535) {
            return fail("Invalid source or target port");
        }
        if (!canConnect(sourcePort, 1200)) return fail("Local ADB source port " + sourcePort + " is not reachable");
        line("Source probe", "127.0.0.1:" + sourcePort + " is open");

        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress("127.0.0.1", sourcePort), 2500);
            socket.setSoTimeout(90000);
            BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
            BufferedOutputStream output = new BufferedOutputStream(socket.getOutputStream());
            KeyPair keys = loadOrCreateKeyPair();

            send(output, A_CNXN, VERSION, MAX_DATA, utf8("host::\0"));
            line("ADB handshake", "CNXN sent; waiting for daemon/authentication");
            boolean connected = authenticate(input, output, keys);
            if (!connected) return fail("ADB authentication did not reach the connected state");
            line("ADB authentication", "Authorized and connected");

            String response = requestTcpPort(input, output, targetPort);
            line("Daemon response", response.length() == 0 ? "Connection closed while adbd restarted" : response.trim());
        } catch (java.net.SocketTimeoutException e) {
            return fail("Timed out waiting for ADB authorization. Approve the RSA dialog and try again");
        } catch (Exception e) {
            line("Exception", e.getClass().getSimpleName() + ": " + safe(e.getMessage()));
        } finally {
            try { socket.close(); } catch (Exception ignored) { }
        }

        line("Verification", "Waiting for adbd to restart on " + targetPort);
        boolean opened = waitForPort(targetPort, 15000);
        boolean oldOpen = canConnect(sourcePort, 800);
        line("Target port " + targetPort, opened ? "OPEN" : "NOT REACHABLE");
        line("Previous port " + sourcePort, oldOpen ? "STILL OPEN" : "closed");
        if (!opened) return fail("ADB command was sent, but port " + targetPort + " did not become reachable");

        String ip = firstIpv4();
        line("RESULT", "SUCCESS");
        if (ip.length() > 0) line("Laptop command", "adb connect " + ip + ":" + targetPort);
        line("Reminder", "Disable ADB or restore port 5555 after diagnostics");
        return new Result(true, "ADB is listening on " + targetPort + (ip.length() > 0 ? "; use adb connect " + ip + ":" + targetPort : ""), log.toString());
    }

    private boolean authenticate(BufferedInputStream input, BufferedOutputStream output, KeyPair keys) throws Exception {
        boolean signatureSent = false;
        boolean publicKeySent = false;
        for (int messages = 0; messages < 20; messages++) {
            Message message = read(input);
            line("Received", name(message.command) + " arg0=" + message.arg0 + " bytes=" + message.data.length);
            if (message.command == A_CNXN) return true;
            if (message.command != A_AUTH || message.arg0 != AUTH_TOKEN) continue;
            if (!signatureSent) {
                send(output, A_AUTH, AUTH_SIGNATURE, 0, signToken(keys.getPrivate(), message.data));
                signatureSent = true;
                line("Authorization", "Tried stored key signature");
            } else if (!publicKeySent) {
                send(output, A_AUTH, AUTH_PUBLIC_KEY, 0, adbPublicKey((RSAPublicKey) keys.getPublic()));
                publicKeySent = true;
                line("Authorization", "Public key sent — approve the Android RSA prompt now");
            } else {
                send(output, A_AUTH, AUTH_SIGNATURE, 0, signToken(keys.getPrivate(), message.data));
                line("Authorization", "Sent signature for follow-up token");
            }
        }
        return false;
    }

    private String requestTcpPort(BufferedInputStream input, BufferedOutputStream output, int port) throws Exception {
        int localId = 1;
        int remoteId = 0;
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        send(output, A_OPEN, localId, 0, utf8("tcpip:" + port + "\0"));
        line("ADB service", "OPEN tcpip:" + port + " sent");
        try {
            for (int messages = 0; messages < 30; messages++) {
                Message message = read(input);
                line("Service packet", name(message.command) + " arg0=" + message.arg0 + " arg1=" + message.arg1 + " bytes=" + message.data.length);
                if (message.command == A_OKAY && message.arg1 == localId) {
                    remoteId = message.arg0;
                } else if (message.command == A_WRTE && message.arg1 == localId) {
                    response.write(message.data);
                    if (remoteId == 0) remoteId = message.arg0;
                    send(output, A_OKAY, localId, remoteId, new byte[0]);
                } else if (message.command == A_CLSE && message.arg1 == localId) {
                    if (remoteId == 0) remoteId = message.arg0;
                    send(output, A_CLSE, localId, remoteId, new byte[0]);
                    break;
                }
            }
        } catch (EOFException ignored) {
            line("ADB service", "Daemon closed the transport during restart");
        } catch (java.net.SocketException ignored) {
            line("ADB service", "Transport reset during daemon restart");
        }
        return new String(response.toByteArray(), "UTF-8");
    }

    private KeyPair loadOrCreateKeyPair() throws Exception {
        File privateFile = new File(context.getFilesDir(), "mg4_adb_private.pk8");
        File publicFile = new File(context.getFilesDir(), "mg4_adb_public.x509");
        KeyFactory factory = KeyFactory.getInstance("RSA");
        if (privateFile.exists() && publicFile.exists()) {
            PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(readFile(privateFile)));
            PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(readFile(publicFile)));
            line("ADB key", "Loaded existing app-private RSA key");
            return new KeyPair(publicKey, privateKey);
        }
        line("ADB key", "Generating new 2048-bit RSA key");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        writeFile(privateFile, pair.getPrivate().getEncoded());
        writeFile(publicFile, pair.getPublic().getEncoded());
        line("ADB key", "Generated and stored privately inside the app");
        return pair;
    }

    private byte[] signToken(PrivateKey key, byte[] token) throws Exception {
        if (token.length != 20) throw new IllegalArgumentException("Unexpected ADB auth token size: " + token.length);
        byte[] digestInfo = new byte[SHA1_DIGEST_INFO_PREFIX.length + token.length];
        System.arraycopy(SHA1_DIGEST_INFO_PREFIX, 0, digestInfo, 0, SHA1_DIGEST_INFO_PREFIX.length);
        System.arraycopy(token, 0, digestInfo, SHA1_DIGEST_INFO_PREFIX.length, token.length);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(digestInfo);
    }

    private byte[] adbPublicKey(RSAPublicKey key) throws Exception {
        BigInteger modulus = key.getModulus();
        BigInteger two32 = BigInteger.ONE.shiftLeft(32);
        BigInteger n0inv = two32.subtract(modulus.modInverse(two32)).and(two32.subtract(BigInteger.ONE));
        BigInteger rr = BigInteger.ONE.shiftLeft(4096).mod(modulus);
        ByteArrayOutputStream binary = new ByteArrayOutputStream(524);
        writeLe32(binary, 64);
        writeLe32(binary, n0inv.longValue());
        binary.write(littleEndian(modulus, 256));
        binary.write(littleEndian(rr, 256));
        writeLe32(binary, key.getPublicExponent().longValue());
        String encoded = Base64.encodeToString(binary.toByteArray(), Base64.NO_WRAP) + " mg4-hardware-probe@mg4\0";
        return encoded.getBytes("UTF-8");
    }

    private static byte[] littleEndian(BigInteger value, int size) {
        byte[] big = value.toByteArray();
        byte[] little = new byte[size];
        for (int i = 0; i < size && i < big.length; i++) little[i] = big[big.length - 1 - i];
        return little;
    }

    private static void send(BufferedOutputStream output, int command, int arg0, int arg1, byte[] data) throws Exception {
        int checksum = 0;
        for (byte b : data) checksum += b & 255;
        ByteBuffer header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(command).putInt(arg0).putInt(arg1).putInt(data.length).putInt(checksum).putInt(command ^ 0xffffffff);
        output.write(header.array());
        output.write(data);
        output.flush();
    }

    private static Message read(BufferedInputStream input) throws Exception {
        byte[] header = readExactly(input, 24);
        ByteBuffer b = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        int command = b.getInt(), arg0 = b.getInt(), arg1 = b.getInt(), length = b.getInt(), checksum = b.getInt(), magic = b.getInt();
        if ((command ^ 0xffffffff) != magic) throw new IllegalStateException("Invalid ADB header magic");
        if (length < 0 || length > 1024 * 1024) throw new IllegalStateException("Invalid ADB payload length " + length);
        byte[] data = readExactly(input, length);
        int actual = 0;
        for (byte x : data) actual += x & 255;
        if (actual != checksum) throw new IllegalStateException("ADB payload checksum mismatch");
        return new Message(command, arg0, arg1, data);
    }

    private boolean waitForPort(int port, long maximumMillis) {
        long end = System.currentTimeMillis() + maximumMillis;
        while (System.currentTimeMillis() < end) {
            if (canConnect(port, 600)) return true;
            try { Thread.sleep(400); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return false; }
        }
        return false;
    }

    private boolean canConnect(int port, int timeoutMillis) {
        Socket socket = new Socket();
        try { socket.connect(new InetSocketAddress("127.0.0.1", port), timeoutMillis); return true; }
        catch (Exception e) { return false; }
        finally { try { socket.close(); } catch (Exception ignored) { } }
    }

    private void listAddresses() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface network = interfaces.nextElement();
                Enumeration<InetAddress> addresses = network.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();
                    if (!address.isLoopbackAddress()) line("Address " + network.getName(), address.getHostAddress());
                }
            }
        } catch (Exception e) { line("Addresses", "Unavailable: " + e); }
    }

    private String firstIpv4() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            String fallback = "";
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface network = interfaces.nextElement();
                Enumeration<InetAddress> addresses = network.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();
                    String host = address.getHostAddress();
                    if (!address.isLoopbackAddress() && host.indexOf(':') < 0) {
                        if ("wlan0".equals(network.getName())) return host;
                        if (fallback.length() == 0) fallback = host;
                    }
                }
            }
            return fallback;
        } catch (Exception e) { return ""; }
    }

    private Result fail(String summary) {
        line("RESULT", "NOT COMPLETED: " + summary);
        line("Recovery", "No system files were changed. If adbd restarted unexpectedly, reboot the head unit and re-enable ADB.");
        return new Result(false, summary, log.toString());
    }

    private void timestamp(String title) {
        log.append(title).append('\n');
        line("Generated", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.US).format(new Date()));
    }
    private void line(String key, String value) { log.append(key).append(": ").append(safe(value)).append('\n'); }
    private static String safe(String value) { return value == null ? "" : value; }
    private static byte[] utf8(String value) throws Exception { return value.getBytes("UTF-8"); }
    private static int command(String text) { return text.charAt(0) | text.charAt(1) << 8 | text.charAt(2) << 16 | text.charAt(3) << 24; }
    private static String name(int command) {
        char[] chars = {(char)(command & 255), (char)((command >>> 8) & 255), (char)((command >>> 16) & 255), (char)((command >>> 24) & 255)};
        return new String(chars);
    }
    private static byte[] hex(String text) {
        byte[] data = new byte[text.length() / 2];
        for (int i = 0; i < data.length; i++) data[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        return data;
    }
    private static byte[] readExactly(BufferedInputStream input, int count) throws Exception {
        byte[] data = new byte[count]; int offset = 0;
        while (offset < count) {
            int n = input.read(data, offset, count - offset);
            if (n < 0) throw new EOFException("ADB transport closed");
            offset += n;
        }
        return data;
    }
    private static void writeLe32(ByteArrayOutputStream output, long value) {
        output.write((int)(value & 255)); output.write((int)((value >>> 8) & 255));
        output.write((int)((value >>> 16) & 255)); output.write((int)((value >>> 24) & 255));
    }
    private static byte[] readFile(File file) throws Exception {
        FileInputStream input = new FileInputStream(file);
        try {
            ByteArrayOutputStream data = new ByteArrayOutputStream(); byte[] block = new byte[4096]; int n;
            while ((n = input.read(block)) >= 0) data.write(block, 0, n);
            return data.toByteArray();
        } finally { input.close(); }
    }
    private static void writeFile(File file, byte[] data) throws Exception {
        FileOutputStream output = new FileOutputStream(file);
        try { output.write(data); output.flush(); output.getFD().sync(); }
        finally { output.close(); }
    }

    static final class Result {
        final boolean success; final String summary; final String log;
        Result(boolean success, String summary, String log) { this.success = success; this.summary = summary; this.log = log; }
    }
    private static final class Message {
        final int command, arg0, arg1; final byte[] data;
        Message(int command, int arg0, int arg1, byte[] data) { this.command = command; this.arg0 = arg0; this.arg1 = arg1; this.data = data; }
    }
}
