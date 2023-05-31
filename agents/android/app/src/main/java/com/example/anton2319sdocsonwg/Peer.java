package com.example.anton2319sdocsonwg;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Peer {
    public String preshared_key;
    public String endpoint;
    public String[] allowed_ips;
    public String id;

    public static Peer fromByteArray(byte[] byteArray) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(byteArray, Peer.class);
    }
}
