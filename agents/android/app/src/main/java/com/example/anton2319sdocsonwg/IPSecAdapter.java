package com.example.anton2319sdocsonwg;

import android.content.Context;
import android.net.VpnService;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import ztandroid.TunAdapter;
import ztandroid.Ztandroid;

public class IPSecAdapter implements TunAdapter {

    int Port;
    String IfaceName;
    String Addr;
    String PreSharedKey;
    int Mtu;

    private static final String ERR_USER_DENIED_CODE = "ERR00";
    private static final String ERR_SETTINGS_CHANGE_UNAVAILABLE_CODE = "ERR01";
    private static final String ERR_FAILED_OPEN_DIALOG_CODE = "ERR02";
    private static final String ERR_INTERNAL_ERROR = "ERR03";

    private static final int REQUEST_CHECK_SETTINGS = 42;

    private final int VPN_PERMISSION_INTENT = 2;

    private Map<String, Peer> peers = new HashMap<String, Peer>();

    Context context;

    IPSecAdapter(int Port, String IfaceName, String Addr, String PreSharedKey, int Mtu) {
        this.Port = Port;
        this.IfaceName = IfaceName;
        this.Addr = Addr;
        this.PreSharedKey = PreSharedKey;
        this.Mtu = Mtu;
    }

    @Override
    public void addUpdateClient(byte[] bytes) throws Exception {
        Peer peer = Peer.fromByteArray(bytes);
        // TODO: implement add ipsec connection

    }

    public String getInterfaceAddress() {
        return this.Addr;
    }

    public String getInterfaceName() {
        return this.IfaceName;
    }

    public long getInterfacePort() {
        return this.Port;
    }

    public String getPublicKey() {

        return "";
    }

    public String getType() {
        return "ipsec";
    }

    public void setupConRoutes(String var1) {

    }

    public void start() {
        // TODO: implement ipsec tunnel start
    }

    public void stop() {
        // TODO: implement ipsec tunnel stop

    }

    public void updateAddress(String var1) {
        this.Addr = var1;
    }

    @Override
    public void updateEndpoint(String id, String endpoint) throws Exception {
        Peer peer = this.peers.get(id);
        peer.endpoint = endpoint;
        this.peers.put(id, peer);

        // workaround for crash issue
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        this.stop();
        this.start();
    }
}
