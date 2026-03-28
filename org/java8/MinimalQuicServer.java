package org.java8; 

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.*;
import java.lang.reflect.Method;

public class MinimalQuicServer {
    private static File tPu = new File(setPathToKey() + "udp_log.txt");
    private static Object logRdpMainSync = new Object();
  
    private String outp = "";
    private boolean printSelf = false;
    private static int QUIC_PORT = 443;
    private static final int MAX_PACKET_SIZE = 1500;
    private final String labelTls = "tls13 ";
  
    private DatagramChannel channel;
    private Selector selector;
    private boolean running = true;
    private static final int MIN_INITIAL_SIZE = 1200;  // RFC 9000: Initial >= 1200 bytes
    private static int AUTH_TAG_LENGTH = 16;
      
    // QUIC 1 (RFC 9000)
    private static final byte[] QUIC_VERSION_1 = {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01};
    private static final byte[] INITIAL_SALT_V1 = {
        (byte)0x38, (byte)0x76, (byte)0x2c, (byte)0xf7,
        (byte)0xf5, (byte)0x59, (byte)0x34, (byte)0xb3,
        (byte)0x4d, (byte)0x17, (byte)0x9a, (byte)0xe6,
        (byte)0xa4, (byte)0xc8, (byte)0x0c, (byte)0xad,
        (byte)0xcc, (byte)0xbb, (byte)0x7f, (byte)0x0a
    };

    // QUIC 2 (RFC 9369)
    private static final byte[] QUIC_VERSION_2 = {(byte)0x6b, (byte)0x33, (byte)0x43, (byte)0xcf};
    private static final byte[] INITIAL_SALT_V2 = {
        (byte)0x0d, (byte)0xed, (byte)0xe3, (byte)0xde,
        (byte)0xf7, (byte)0xa0, (byte)0xf7, (byte)0xc7,
        (byte)0x31, (byte)0x0b, (byte)0x03, (byte)0x35,
        (byte)0x0a, (byte)0x17, (byte)0x38, (byte)0x31,
        (byte)0x0d, (byte)0x16, (byte)0xed, (byte)0xeb,
        (byte)0x1e, (byte)0x38, (byte)0x48, (byte)0x03
    };
  
    private static final String HMAC_SHA256 = "HmacSHA256";
  
    private ConcurrentHashMap<ByteArrayWrapper, ConnectionState> connections = new ConcurrentHashMap<ByteArrayWrapper, ConnectionState>();

    public static void runMe() throws Exception {
        Thread one = new Thread() {
            public void run() {
                try {
                  main(new String[0]);
                } catch(Exception sd) {
                }
            }  
        };    
        one.start();
        //main(new String[0]);
    }

    public static void main(String[] args) throws Exception {
        MinimalQuicServer server = new MinimalQuicServer();
        if(args != null && args.length > 0) {
          try {
            int a = Integer.parseInt(args[0]);
            if(a > 0) {
              QUIC_PORT = a;
              server.System_out_println(" Own listening port: " + a);
            }
          } catch(Exception sd) { }
        }          
        server.start();
    }
  
    public void start() throws Exception {
        if(tPu.exists()) {
          try { 
            tPu.delete(); 
            tPu.createNewFile();
            System_out_println("File udp_log.txt exists: " + tPu.exists() + " > " + tPu.getCanonicalPath());
          } catch(Exception sd) { }      
        }
        System_out_println("Listening on UDP port " + QUIC_PORT);
        System_out_println("Will decrypt Initial packets and extract TLS 1.3 ClientHello");
    
        channel = DatagramChannel.open();
        channel.configureBlocking(false);
        channel.socket().bind(new InetSocketAddress(QUIC_PORT));
      
        selector = Selector.open();
        channel.register(selector, SelectionKey.OP_READ);
      
        while (running) {
            selector.select(100);
          
            Set<SelectionKey> keys = selector.selectedKeys();
            Iterator<SelectionKey> iter = keys.iterator();
          
            while (iter.hasNext()) {
                SelectionKey key = iter.next();
                iter.remove();
              
                if (key.isReadable()) {
                    handleIncomingPacket();
                }
            }
        }
      
        cleanup();
    }
   
    private void handleIncomingPacket() throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(MAX_PACKET_SIZE);
        SocketAddress clientAddress = channel.receive(buffer);
      
        if (clientAddress == null) {
           return;
        }
        buffer.flip();
        handleIncomingPacket(buffer, clientAddress);
    }                
    
    private void handleIncomingPacket(ByteBuffer buffer, SocketAddress clientAddress) throws Exception {
        QuicPacket packet = parseQuicPacketExactStyle(buffer, clientAddress);
        if (packet != null && packet.isInitial) {
            System_out_println("? Initial packet detected");
            System_out_println(" DCID length: " + packet.destinationConnectionId.length);
            System_out_println(" SCID length: " + packet.sourceConnectionId.length);
            System_out_println(" Token length: " + packet.token.length);
            System_out_println(" Payload length: " + packet.payloadLength);
 
            ByteArrayWrapper dcidWrap = new ByteArrayWrapper(packet.destinationConnectionId); 
            ConnectionState tempState = new ConnectionState();
            ConnectionState state;
            if((state = connections.putIfAbsent(dcidWrap, tempState)) == null) {
              state = tempState;
              state.lastDCID = packet.destinationConnectionId;
            } else { //state already in memory
              if(state.lastDCID == null) {
                state.lastDCID = packet.destinationConnectionId;
                System_out_println(" Previous packet was unexpectedly null");
              } else {
                packet.destinationConnectionId = state.lastDCID;
              }
            }
    
            DecryptedInitialPacket decrypted = decryptInitialPacketStyle(packet, buffer, state);
          
            if (decrypted != null) {
                processCryptoFrames(decrypted, state, clientAddress);
            }
        }
    }
  
    private QuicPacket parseQuicPacketExactStyle(ByteBuffer buffer, SocketAddress clientAddress) {
        if (buffer.remaining() < 7) {
            System_out_println(" ? Packet too short (min 7 bytes required)");
            return null;
        }
        QuicPacket packet = new QuicPacket();
        int startPos = buffer.position();

        try {
            byte firstByte = buffer.get();
            packet.firstByte = firstByte;
            packet.isLongHeader = (firstByte & 0x80) != 0;
          
            if (!packet.isLongHeader) {
                System_out_println(" Short header packet (not supported in demo)");
                return null;
            }
          
            //packet.type = (byte)((firstByte & 0x30) >> 4);
            //packet.isInitial = (packet.type == 0x00);
          
            System_out_println(" \r\n\r\nNEW\r\nFirst byte: 0x" + String.format("%02X", firstByte));
            //System_out_println(" Packet type: " + packet.type + " (0=Initial)");
          
            packet.version = new byte[4];
            buffer.get(packet.version);
            System_out_println(" Version: " + bytesToHex(packet.version, 4));
          
            // QUIC v1
            packet.isVersion = 1;
            for (int i = 0; i < QUIC_VERSION_1.length; i++) {
                if (packet.version[i] != QUIC_VERSION_1[i]) { 
                    packet.isVersion = 2;
                    for (i = 0; i < QUIC_VERSION_2.length; i++) {
                        if (packet.version[i] != QUIC_VERSION_2[i]) {
                           packet.isVersion = 0;
                           break;
                        }
                    }
                    break;
                }
            }

            packet.type = (byte)((firstByte & 0x30) >> 4);

            String typeName;
            boolean isInitial = false;

            if (packet.isVersion == 1) {
                switch (packet.type) {
                    case 0x00: 
                      typeName = "Initial";   
                      isInitial = true; 
                    break;
                    case 0x01: typeName = "0-RTT";     break;
                    case 0x02: typeName = "Handshake"; break;
                    case 0x03: typeName = "Retry";     break;
                    default:   typeName = "Unknown";   break;
                }
            } else if (packet.isVersion == 2) { //isQuicV2(packet.version)
                switch (packet.type) {
                    case 0x01: 
                      typeName = "Initial";   
                      isInitial = true;
                    break;
                    case 0x02: typeName = "0-RTT";     break;
                    case 0x03: typeName = "Handshake"; break;
                    case 0x00: typeName = "Retry";     break;
                    default:   typeName = "Unknown";   break;
                }
            } else {
                typeName = "Unsupported version";
            }

            packet.isInitial = isInitial;
            System_out_println(" Packet type: 0x" + String.format("%02X", packet.type) + 
                               " → " + typeName + " (version " + 
                               packet.isVersion + ")");

            int dcidLength = buffer.get() & 0xFF;
            System_out_println(" DCID length byte: 0x" + String.format("%02X", dcidLength) + " = " + dcidLength + " bytes");
            if (buffer.remaining() < dcidLength) {
                System_out_println(" ? Not enough data for DCID");
                return null;
            }
     
            packet.destinationConnectionId = new byte[dcidLength];
            buffer.get(packet.destinationConnectionId);
            System_out_println(" DCID: " + bytesToHex(packet.destinationConnectionId)); 
         
            int scidLength = buffer.get() & 0xFF;
            System_out_println(" SCID length byte: 0x" + String.format("%02X", scidLength) + " = " + scidLength + " bytes");
            if (buffer.remaining() < scidLength) {
                System_out_println(" ? Not enough data for SCID");
                return null;
            }
            packet.sourceConnectionId = new byte[scidLength];
            buffer.get(packet.sourceConnectionId);
        
           
            if (packet.isVersion == 0) {
                System_out_println(" Not QUIC v1 or v2 packet");    
                sendVersionNegotiation(packet, clientAddress);   
                return null;
            }         
      
            if (packet.isInitial) {
                VarLenResult tokenLen = readVariableLength(buffer);
                if (tokenLen.size == 0) {
                    System_out_println(" ? Failed to read token length");
                    return null;
                }
                int tokenLength = (int) tokenLen.value;
                System_out_println(" Token length: " + tokenLength + " bytes < " + tokenLen.size);
                if (tokenLength > 0) {
                    if (buffer.remaining() < tokenLength) {
                        System_out_println(" ? Not enough data for token");
                        return null;
                    }
                    packet.token = new byte[tokenLength];
                    buffer.get(packet.token);
                } else {
                    packet.token = new byte[0];
                }
            }
          
            int payloadLengthStart = buffer.position();
            VarLenResult payloadLen = readVariableLength(buffer);
            int positionBeforeSample = buffer.position();
            if (payloadLen.size == 0) {
                System_out_println(" ? Failed to read payload length");
                return null;
            }
            packet.payloadLength = (int) payloadLen.value; //packet length
            System_out_println(" Payload length: " + packet.payloadLength + " bytes");
          
            if (buffer.remaining() < packet.payloadLength) {
                System_out_println(" ? Not enough data for payload");
                return null;
            }
            buffer.position(positionBeforeSample);
            System_out_println(" ? Successfully parsed packet structure");
            return packet;
          
        } catch (Exception e) {
            System_out_println(" ? Error parsing packet: " + e.getMessage());
            buffer.position(startPos);
            return null;
        }
    }
  
    private VarLenResult readVariableLength(byte[] data, int offset) {
       ByteBuffer buffer = ByteBuffer.wrap(data);
       buffer.position(offset);
       return readVariableLength(buffer);
    }
  
    private VarLenResult readVariableLength(ByteBuffer buffer) {
        if (!buffer.hasRemaining()) {
           System_out_println("No remaining bytebuffer data: 1");
           return new VarLenResult(0, 0);
        }
        int startPos = buffer.position();
        try {
            int firstByte = buffer.get() & 0xFF;
            int length;
            long value;
          
            switch ((firstByte & 0xC0) >>> 6) {
                case 0:
                    length = 1;
                    value = firstByte & 0x3F;
                    break;
                case 1:
                    length = 2;
                    if (!buffer.hasRemaining()) {
                        buffer.position(startPos);
                        System_out_println("No remaining bytebuffer data: 2");
                        return new VarLenResult(0, 0);
                    }
                    value = ((firstByte & 0x3F) << 8) | (buffer.get() & 0xFF);
                    break;
                case 2:
                    length = 4;
                    if (buffer.remaining() < 3) {
                        buffer.position(startPos);
                        System_out_println("No remaining bytebuffer data: 3");
                        return new VarLenResult(0, 0);
                    }
                    value = ((firstByte & 0x3F) << 24) |
                           ((buffer.get() & 0xFF) << 16) |
                           ((buffer.get() & 0xFF) << 8) |
                           (buffer.get() & 0xFF);
                    break;
                case 3:
                    length = 8;
                    if (buffer.remaining() < 7) {
                        buffer.position(startPos);
                        System_out_println("No remaining bytebuffer data: 4");
                        return new VarLenResult(0, 0);
                    }
                    value = ((long)(firstByte & 0x3F) << 56) |
                           ((long)(buffer.get() & 0xFF) << 48) |
                           ((long)(buffer.get() & 0xFF) << 40) |
                           ((long)(buffer.get() & 0xFF) << 32) |
                           ((long)(buffer.get() & 0xFF) << 24) |
                           ((long)(buffer.get() & 0xFF) << 16) |
                           ((long)(buffer.get() & 0xFF) << 8) |
                           (buffer.get() & 0xFF);
                    break;
                default:
                    buffer.position(startPos);
                    System_out_println("No remaining bytebuffer data: 5");
                    return new VarLenResult(0, 0);
            }
            return new VarLenResult(value, length);
        } catch (Exception e) {
            buffer.position(startPos);
            System_out_println("  No remaining bytebuffer data: 6");
            e.printStackTrace(System.out);
            return new VarLenResult(0, 0);
        }
    }
  
    private DecryptedInitialPacket decryptInitialPacketStyle(QuicPacket packet, ByteBuffer buffer, ConnectionState state) throws Exception {
   
       System_out_println("\n Decrypting Initial packet... " + buffer.position());
      //int oldPosition = buffer.position();
      //for(;;) {
        //System_out_println(" 1. Computing initial secrets...");
        byte[] salt = packet.isVersion == 1 ? INITIAL_SALT_V1 : INITIAL_SALT_V2;
        byte[] initialSecret = hkdfExtract(salt, packet.destinationConnectionId);      
        byte[] clientInitialSecret = hkdfExpandLabel(initialSecret, getInLabel(packet.isVersion, true), new byte[0], 32);        
        byte[] clientKey = hkdfExpandLabel(clientInitialSecret, getKeyLabel(packet.isVersion), new byte[0], 16);
        byte[] clientIv = hkdfExpandLabel(clientInitialSecret, getIvLabel(packet.isVersion), new byte[0], 12);
        byte[] clientHpKey = hkdfExpandLabel(clientInitialSecret, getHpLabel(packet.isVersion), new byte[0], 16);
    
        System_out_println(" Initial Secret (own HKDF-Extract): " + bytesToHex(initialSecret));    
        System_out_println(" Client Initial Secret (with 'client in' label): " + bytesToHex(clientInitialSecret));        
        System_out_println(" Client Key: " + bytesToHex(clientKey));
        System_out_println(" Client IV: " + bytesToHex(clientIv));
        System_out_println(" Client HP Key: " + bytesToHex(clientHpKey));
    
        //int oldPosition = buffer.position();
        //try {
        //  testDecryptResponse(buffer, -1, -1, clientKey, clientIv, clientHpKey); 
        //} catch(Exception sd) { }
        //buffer.position(oldPosition);
    
        System_out_println(" 3. Removing header protection...");
      
        if (packet.payloadLength < 20) {
            System_out_println(" ? Payload too short for sample");
            return null;
        }
   
        int currentPosition = buffer.position();
        if (buffer.remaining() < 4) {
            return null;
        }
        buffer.position(currentPosition + 4);
        if (buffer.remaining() < 16) {
            return null;
        }
        //int sampleStart = 4;
        //byte[] sample2 = Arrays.copyOfRange(packet.encryptedPayload, 4,
        // Math.min(4 + 16, packet.encryptedPayload.length));
        byte[] sample = new byte[16];
        buffer.get(sample);
        System_out_println(" Sample (bytes 4-20): " + bytesToHex(sample));
      
        byte[] mask = generateAes128Ecb(clientHpKey, sample);
        System_out_println(mask.length + " Mask (first 5): " + bytesToHex(mask));
      
        byte firstByte = packet.firstByte;
        byte unmaskedFirstByte;
        if ((firstByte & 0x80) == 0x80) {
            unmaskedFirstByte = (byte) (firstByte ^ mask[0] & 0x0f);
        } else {
            unmaskedFirstByte = (byte) (firstByte ^ mask[0] & 0x1f);
        }
        buffer.position(currentPosition);
        System_out_println(" First byte: 0x" + String.format("%02X", firstByte) +
                         " -> 0x" + String.format("%02X", unmaskedFirstByte));
      
        int pnLength = (unmaskedFirstByte & 0x03) + 1;
        System_out_println(" Protected packet number length: " + pnLength + " bytes");
      
        //int authTagLength = 16;
        //if (packet.encryptedPayload.length < authTagLength + pnLength) {
        // System_out_println(" ? Payload too short for PN and auth tag");
        // return null;
        //}
      
        //int pnOffset = 0;
        //System_out_println(" pnOffset: " + pnOffset);
        byte[] encryptedPn = new byte[pnLength]; //Arrays.copyOfRange(packet.encryptedPayload, pnOffset, pnOffset + pnLength);
        buffer.get(encryptedPn);
        System_out_println("  Encrypted pn-holder len: " + encryptedPn.length + " follow position: " + buffer.position());
        byte[] decryptedPn = new byte[pnLength];
      
        for (int i = 0; i < pnLength; i++) {
            decryptedPn[i] = (byte)(encryptedPn[i] ^ mask[i + 1]);
        }
      
        long packetNumber = decodePacketNumber(bytesToLong(decryptedPn), state.largestPacketNumber, pnLength * 8);
        packet.packetNumber = packetNumber;
        if (packetNumber > state.largestPacketNumber) {
            state.largestPacketNumber = packetNumber;
        }
        System_out_println(" Packet number: " + bytesToLong(decryptedPn) + " > " + packetNumber);
        currentPosition = buffer.position();
   
        byte[] frameHeader = new byte[currentPosition];
        buffer.position(0);
        buffer.get(frameHeader);
        frameHeader[0] = unmaskedFirstByte;
        buffer.position(currentPosition);
   
        System.arraycopy(decryptedPn, 0, frameHeader, frameHeader.length - pnLength, pnLength);
   
        System_out_println(" 4. Decrypting with AES-128-GCM...");
        
        int encryptedPayloadLength = packet.payloadLength - pnLength;
        if (encryptedPayloadLength < 1) {
            System_out_println(" ? Encrypted payload extraction failed!");
            return null;
        }
        byte[] payload = new byte[encryptedPayloadLength];
        buffer.get(payload); //, 0, encryptedPayloadLength
        byte[] nonce = computeNonce(clientIv, packetNumber, pnLength);
        System_out_println(" Nonce: " + bytesToHex(nonce) + " > cipher with tag len: " + payload.length + " > aad len: " + frameHeader.length);
        
        byte[] decryptedPayload = decryptAes128Gcm(clientKey, nonce, payload, frameHeader); //, authTag
        
        if (decryptedPayload == null) {
            System_out_println(" ? GCM decryption failed: " + state.lastDCID);   
            return null;
        }
      
        System_out_println(" ? Decryption successful!");
        System_out_println(" Decrypted payload length: " + decryptedPayload.length);
      
        DecryptedInitialPacket result = new DecryptedInitialPacket();
        result.packet = packet;
        result.decryptedPayload = decryptedPayload;
        result.clientKey = clientKey;
        result.clientIv = clientIv;
        
        return result;
      //}
    }
     
    private byte[] hkdfExpandLabel(byte[] secret, String label, byte[] context, int length) throws Exception {
        byte[] labelBytes = (labelTls + label).getBytes();
        byte[] hkdfLabel = new byte[2 + 1 + labelBytes.length + 1 + context.length];
        hkdfLabel[0] = (byte)(length >> 8);
        hkdfLabel[1] = (byte)length;
        hkdfLabel[2] = (byte)labelBytes.length;
        System.arraycopy(labelBytes, 0, hkdfLabel, 3, labelBytes.length);
        hkdfLabel[3 + labelBytes.length] = (byte)context.length;
        if (context.length > 0) {
            System.arraycopy(context, 0, hkdfLabel, 4 + labelBytes.length, context.length);
        }
        return hkdfExpand(secret, hkdfLabel, length);
    }
  
    private byte[] hkdfExtract(byte[] salt, byte[] ikm) throws Exception {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        SecretKeySpec key = new SecretKeySpec(salt, HMAC_SHA256);
        mac.init(key);
        return mac.doFinal(ikm);
    }
  
    private byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws Exception {
        Mac hmac = Mac.getInstance(HMAC_SHA256);
        SecretKeySpec key = new SecretKeySpec(prk, HMAC_SHA256);
        hmac.init(key);
        byte[] blockN = new byte[0];
        int iterations = (int) Math.ceil(((double) length) / ((double) hmac.getMacLength()));
        if (iterations > 255) throw new IllegalArgumentException("out length must be maximal 255 * hash-length");
        ByteBuffer buffer = ByteBuffer.allocate(length);
        int remainingBytes = length;
        int stepSize;
        for (int i = 0; i < iterations; i++) {
            hmac.update(blockN);
            hmac.update(info);
            hmac.update((byte) (i + 1));
            blockN = hmac.doFinal();
            stepSize = Math.min(remainingBytes, blockN.length);
            buffer.put(blockN, 0, stepSize);
            remainingBytes -= stepSize;
        }
        return buffer.array();
    }
  
    private byte[] generateAes128Ecb(byte[] key, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] input16 = new byte[16];
        System.arraycopy(input, 0, input16, 0, Math.min(input.length, 16));
        return cipher.doFinal(input16);
    }
  
    private byte[] decryptAes128Gcm(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) //, byte[] authTag
            throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            if (aad != null && aad.length > 0) {
               cipher.updateAAD(aad);
            }
            //byte[] combined = new byte[ciphertext.length + authTag.length];
            //System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
            //System.arraycopy(authTag, 0, combined, ciphertext.length, authTag.length);
            //return cipher.doFinal(combined);
            return cipher.doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            System_out_println(" ? Tag mismatch: " + e.getMessage());
            return null;
        } catch (Exception e) {
            System_out_println(" ? GCM error: " + e.getMessage());
            return null;
        }
    }
  
    private byte[] computeNonce(byte[] iv, long packetNumber, int pnLength) {
        ByteBuffer nonceInput = ByteBuffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong(packetNumber);
    
        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array()) {
            nonce[i] = (byte) (b ^ iv[i++]); 
        }
        return nonce;
    }
  
    private static long decodePacketNumber(long truncatedPacketNumber, long largestPacketNumber, int bits) {
        long expectedPacketNumber = largestPacketNumber + 1;
        long pnWindow = 1L << bits;
        long pnHalfWindow = pnWindow / 2;
        long pnMask = ~(pnWindow - 1);
        long candidatePn = (expectedPacketNumber & pnMask) | truncatedPacketNumber;
        if (candidatePn <= expectedPacketNumber - pnHalfWindow && candidatePn < (1L << 62) - pnWindow) {
            return candidatePn + pnWindow;
        }
        if (candidatePn > expectedPacketNumber + pnHalfWindow && candidatePn >= pnWindow) {
            return candidatePn - pnWindow;
        }
        return candidatePn;
    }
  
    private long bytesToLong(byte[] bytes) {
        long value = 0;
        for (byte b : bytes) {
            value = (value << 8) | (b & 0xFF);
        }
        return value;
    }
  
    private String bytesToHex(byte[] bytes) {
        return bytesToHex(bytes, bytes.length);
    }
  
    private String bytesToHex(byte[] bytes, int maxLength) {
        if (bytes == null || bytes.length == 0) return "empty";
        StringBuilder sb = new StringBuilder();
        int length = Math.min(bytes.length, maxLength);
        for (int i = 0; i < length; i++) {
            sb.append(String.format("%02X", bytes[i] & 0xFF));
            if (i < length - 1) sb.append(" ");
        }
        if (bytes.length > maxLength) sb.append("...");
        return sb.toString();
    }
  
    private void processCryptoFrames(DecryptedInitialPacket decrypted, ConnectionState state, SocketAddress clientAddress) throws IOException {
        System_out_println("\n?? Analyzing CRYPTO frames for TLS 1.3 ClientHello...");
        state.partialCryptoLen = 0;
        byte[] data = decrypted.decryptedPayload;

        int offset = 0;
        boolean foundCryptoFrame = false;
       
        while (offset < data.length) {
            //if (offset >= data.length) { break; }
           
            byte frameType = data[offset++];
           
            System_out_println(" Frame type at offset " + (offset - 1) + ": 0x" + String.format("%02X", frameType) + " > packetNumber > " + decrypted.packet.packetNumber);
           
            // CRYPTO frame type = 0x06
            if (frameType == 0x06) {
                foundCryptoFrame = true;
                System_out_println(" ? Found CRYPTO frame (0x06)");
               
                VarLenResult offsetResult = readVariableLength(data, offset);
                offset += offsetResult.size;
               
                long cryptoOffset = offsetResult.value;
               
                VarLenResult lengthResult = readVariableLength(data, offset);
                offset += lengthResult.size;
               
                int cryptoDataLength = (int)lengthResult.value;
               
                System_out_println(" Offset: " + offsetResult.value + " > " + offsetResult.size + ":" + lengthResult.size);
                System_out_println(" Length: " + cryptoDataLength + " bytes");
               
                if (offset + cryptoDataLength <= data.length) {
                    byte[] cryptoData = Arrays.copyOfRange(data, offset, offset + cryptoDataLength);
                    //System_out_println("CRYPTOFRAME DATA: \r\n" + new String(cryptoData)); //bytesToHex(cryptoData);
                    state.cryptoChunks.put(cryptoOffset, cryptoData);
                    state.fullCryptoLen += cryptoData.length;
                    state.partialCryptoLen += cryptoData.length;
                    System_out_println(" Added CRYPTO chunk at offset " + cryptoOffset + " length " + cryptoDataLength);
                   
                    offset += cryptoDataLength;
                } else {
                    System_out_println(" ? Not enough data for CRYPTO frame");
                    break;
                }
            } else if (frameType == 0x00) { // PADDING frame (0x00) -
                while (offset < data.length && data[offset] == 0x00) {
                    offset++;
                }
                System_out_println(" Padding frame, skipping...");
            } else if (frameType == 0x01) { // PING frame (0x01) -
                System_out_println(" PING frame, skipping...");
                // PING frame
            } else if (frameType == 0x02 || frameType == 0x03) { // ACK frame (0x02-0x03) -
                System_out_println(" ACK frame, skipping...");
                offset = skipAckFrame(data, offset);
            } else if (frameType == 0x1c || frameType == 0x1d) { // CONNECTION_CLOSE frame (0x1c-0x1d) -
                System_out_println(" CONNECTION_CLOSE frame, skipping...");
                offset = skipConnectionCloseFrame(data, offset, frameType);
                if(connections.remove(new ByteArrayWrapper(decrypted.packet.destinationConnectionId)) != null) {
                  System_out_println(" CONNECTION_CLOSE removed DCID...");
                  if(state != null && state.subsequentSCID != null && connections.remove(state.subsequentSCID) != null) {
                    System_out_println(" CONNECTION_CLOSE removed DCID subsequent...");                  
                  }
                } else {
                  System_out_println(" CONNECTION_CLOSE failed to remove DCID...");
                }
            } else if (frameType >= 0x08 && frameType <= 0x0f) { //0x09,0x0a,0x0b,0x0c,0x0d,0x0e 
                System_out_println(" STREAM frame, skipping...");        
                offset = parseStreamFrame(data, frameType, offset);        
            } else { // Unknown frame - try to skip
                System_out_println(" Unknown frame type: 0x" + String.format("%02X", frameType) + ", stopping analysis");
                break;
            }
        }
       
        if (!foundCryptoFrame) {
            System_out_println(" ? No CRYPTO frame found in decrypted payload");
        }

        tryExtractClientHello(state, decrypted, clientAddress);
    }

    private void tryExtractClientHello(ConnectionState state, DecryptedInitialPacket decrypted, SocketAddress clientAddress)  throws IOException {
        //if (state.helloExtracted) { return; }

        long currentOffset = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while (true) {
            Map.Entry<Long, byte[]> entry = state.cryptoChunks.ceilingEntry(currentOffset);
            if (entry == null || entry.getKey() > currentOffset) { break; } // gap
            if (entry.getKey() != currentOffset) {
                System_out_println(" Overlap or misorder at offset " + currentOffset);
                return;
            }
            try {
                baos.write(entry.getValue());
            } catch (IOException e) {
                // shouldn't happen
            }
            currentOffset += entry.getValue().length;
        }

        byte[] assembled = baos.toByteArray();
        if (assembled.length < 4) {
            System_out_println(" Assembled too short for header: " + assembled.length);
            return;
        }

        byte handshakeType = assembled[0];
        if (handshakeType != 0x01) {
            System_out_println(" Not ClientHello: 0x" + String.format("%02X", handshakeType));
            return;
        }

        int handshakeLength = ((assembled[1] & 0xFF) << 16) | ((assembled[2] & 0xFF) << 8) | (assembled[3] & 0xFF);
        if (assembled.length < 4 + handshakeLength) {
            System_out_println(" Assembled " + assembled.length + " < needed " + (4 + handshakeLength) + " > " + state.fullCryptoLen + " partial: " + state.partialCryptoLen);
            return;
        } else {
            System_out_println(" Assembled " + assembled.length + " <> handshake " + (4 + handshakeLength) + " > " + state.fullCryptoLen + " partial: " + state.partialCryptoLen);    
        }

        byte[] clientHelloData = Arrays.copyOfRange(assembled, 0, 4 + handshakeLength);
        analyzeTlsHandshake(state, clientHelloData);
        //state.helloExtracted = true;
        state.cryptoChunks.clear();
        state.fullCryptoLen = 0;
        System_out_println("\n? SUCCESS: ClientHello extracted!\r\n");
        //System_out_println("Server stopping as requested...");
        //running = false;

        // CONNECTION_CLOSE
        if (clientAddress != null) {
            //sendConnectionClose(decrypted.packet, state, clientAddress);
            sendVersionNegotiation(decrypted.packet, clientAddress);
        }
    }
  
    private void sendVersionNegotiation(QuicPacket incomingPacket, SocketAddress clientAddress) throws IOException { // throws Exception
        // Format VERSION_NEGOTIATION
        byte headerForm = (byte) ((byte)  (new java.util.Random()).nextInt(256) | 0b11000000); //(byte) 0xC0; // Long header
        byte[] version = new byte[] { 0x00, 0x00, 0x00, 0x00 }; // 0 for VN

        byte[] dcid = incomingPacket.sourceConnectionId; // Echo client's SCID as DCID
        byte dcidLen = (byte) (dcid.length & 0xFF);

        byte[] scid = incomingPacket.destinationConnectionId; // Echo client's DCID as SCID
        byte scidLen = (byte) (scid.length & 0xFF);

        // Supported versions: v1 and v2
        byte[] supportedVersions = new byte[] { 
            0x00, 0x00, 0x00, 0x01,  // QUIC v1
            0x6b, 0x33, 0x43, (byte)0xcf   // QUIC v2
        };
        //byte[] supportedVersions = new byte[] {  
            //0x0a, 0x0a, 0x0a, 0x0a,  // 0x0a0a0a0a 
            //0x1a, 0x1a, 0x1a, 0x1a   // 0x1a1a1a1a 
        //};    
        ByteArrayOutputStream packetStream = new ByteArrayOutputStream();
        packetStream.write(headerForm);
        packetStream.write(version);
        packetStream.write(dcidLen);
        packetStream.write(dcid);
        packetStream.write(scidLen);
        packetStream.write(scid);
        packetStream.write(supportedVersions);

        byte[] vnPacket = packetStream.toByteArray();

        // Send
        ByteBuffer sendBuffer = ByteBuffer.wrap(vnPacket);
        channel.send(sendBuffer, clientAddress);
        System.out.println("Sent VERSION_NEGOTIATION to " + clientAddress + " with supported versions v1 and v2");
    }  
    
    private int encodePnLen(long packetNumber) {
        if (packetNumber < 0x100L) {
            return 1;
        } else if (packetNumber < 0x10000L) {
            return 2;
        } else if (packetNumber < 0x1000000L) {
            return 3;
        } else {
            return 4;
        }
    }

    // Helper: size of varint for a value
    private int getVarIntSize(long value) {
        if (value < (1L << 6)) return 1;
        if (value < (1L << 14)) return 2;
        if (value < (1L << 30)) return 4;
        return 8;
    }
    
    private byte[] createConnectionCloseTransport(long errorCode, String reason) throws Exception {
        System_out_println("Send transport close");
        ByteArrayOutputStream frames = new ByteArrayOutputStream();
        frames.write(0x1c); // TRANSPORT_CLOSE
        writeVariableLength(errorCode, frames);
        writeVariableLength(0, frames); // Frame Type = 0 (PADDING)   no specific frame triggered the error
        byte[] reasonBytes = reason.getBytes("UTF-8");
        writeVariableLength(reasonBytes.length, frames);  // reason phrase length
        frames.write(reasonBytes);                   // reason phrase bytes
        return frames.toByteArray();
    }

    private byte[] createConnectionCloseApplication(long errorCode, String reason) throws Exception {
        System_out_println("Send application close due 0-RTT");
        ByteArrayOutputStream frames = new ByteArrayOutputStream();
        frames.write(0x1d); // APPLICATION_CLOSE
        writeVariableLength(errorCode, frames); // error_code = H3_VERSION_FALLBACK
        byte[] reasonBytes = reason.getBytes("UTF-8");
        writeVariableLength(reasonBytes.length, frames);  // reason phrase length
        frames.write(reasonBytes);                   // reason phrase bytes
        return frames.toByteArray();
    }
  
    private void sendConnectionClose(QuicPacket clientPacket, ConnectionState state, SocketAddress clientAddress) {
        System_out_println("\n=== Sending CONNECTION_CLOSE ===");
    
        try {
            byte[] dcid = clientPacket.sourceConnectionId;           // DCID of response = client's SCID
            byte[] scid = new byte[8];                               // Our SCID (can be 8 bytes)
            new SecureRandom().nextBytes(scid);

            state.subsequentSCID = new ByteArrayWrapper(scid);
            connections.putIfAbsent(state.subsequentSCID, state);
      
            System_out_println(" SCID back: " + bytesToHex(scid)); 
            // 1. Compute Server Initial Secrets
            byte[] salt = clientPacket.isVersion == 1 ? INITIAL_SALT_V1 : INITIAL_SALT_V2;
            byte[] initialSecret = hkdfExtract(salt, clientPacket.destinationConnectionId);
            byte[] serverSecret = hkdfExpandLabel(initialSecret, getInLabel(clientPacket.isVersion, false), new byte[0], 32);
            byte[] serverKey = hkdfExpandLabel(serverSecret, getKeyLabel(clientPacket.isVersion), new byte[0], 16);
            byte[] serverIv  = hkdfExpandLabel(serverSecret, getIvLabel(clientPacket.isVersion),  new byte[0], 12);
            byte[] serverHp  = hkdfExpandLabel(serverSecret, getHpLabel(clientPacket.isVersion),  new byte[0], 16);
    
            long packetNumber = state.packetNumberSent++; 
            int pnLength = encodePnLen(packetNumber); //4;   //      

            // 2. Create basic CONNECTION_CLOSE frame (0x1d for application error)
            byte[] framesBytes = !state.isZeroRTT ? 
                                 createConnectionCloseTransport(0x0a, "PROTOCOL_VIOLATION: HTTP/1.1 fallback required") :
                                 createConnectionCloseApplication(0x110, "HTTP/3 not supported on this origin");
            int framesSize = framesBytes.length;
    
            // 3. Build unprotected header WITHOUT payload_len
            ByteArrayOutputStream headerBase = new ByteArrayOutputStream();
            
            int typeBits = clientPacket.isVersion == 2 ? 0x01 : 0x00;  // Initial bit pattern
            byte unprotectedFirstByte = (byte) (
                0xC0 |                    // Long header
                (typeBits << 4) |         // Packet type bits (5-4)
                (pnLength - 1)            // Packet number length
            );
            
            headerBase.write(unprotectedFirstByte);
            headerBase.write(clientPacket.version);  // Use client's version
            headerBase.write(dcid.length); 
            headerBase.write(dcid);
            headerBase.write(scid.length); 
            headerBase.write(scid);
            writeVariableLength(0, headerBase);               // Token length = 0
            int headerBaseSize = headerBase.size();
    
            // 4. Estimate payload_len varint size (conservative 4 bytes)
            int estimatedPayloadLenSize = 2; //4;
    
            // 5. Calculate minimum padding
            int minPayloadLength = MIN_INITIAL_SIZE - (headerBaseSize + estimatedPayloadLenSize);
            int paddingNeeded = Math.max(0, minPayloadLength - (pnLength + framesSize + AUTH_TAG_LENGTH));
    
            System_out_println("Initial calc: headerBase=" + headerBaseSize + ", estPayloadLenSize=" + estimatedPayloadLenSize + 
                               ", pnLength=" + pnLength + ", frames=" + framesSize + ", paddingNeeded=" + paddingNeeded);
    
            // Add padding
            ByteArrayOutputStream payloadPlainStream = new ByteArrayOutputStream();
            payloadPlainStream.write(framesBytes);
            for (int i = 0; i < paddingNeeded; i++) {
                payloadPlainStream.write(0x00);
            }
            byte[] payloadPlain = payloadPlainStream.toByteArray();
    
            // 6. PN bytes
            byte[] pnBytes = longToBytes(packetNumber, pnLength);
    
            // 7. Compute payload_length = pnLength + len(payloadPlain) + AUTH_TAG_LENGTH
            int payloadLength = pnLength + payloadPlain.length + AUTH_TAG_LENGTH;
    
            // 8. Build full unprotected header
            ByteArrayOutputStream fullHeader = new ByteArrayOutputStream();
            fullHeader.write(headerBase.toByteArray());
            writeVariableLength(payloadLength, fullHeader);
            byte[] unprotectedHeader = fullHeader.toByteArray();
    
            // 9. AAD = unprotectedHeader + pnBytes
            ByteArrayOutputStream aadStream = new ByteArrayOutputStream();
            aadStream.write(unprotectedHeader);
            aadStream.write(pnBytes);
            byte[] aad = aadStream.toByteArray();
    
            // 10. Encrypt payloadPlain
            byte[] nonce = computeNonce(serverIv, packetNumber, pnLength);
            byte[] encryptedPayload = encryptAes128Gcm(serverKey, nonce, payloadPlain, aad);
    
            if (encryptedPayload == null) {
                throw new Exception("Encryption failed");
            }
    
            if (encryptedPayload.length != payloadPlain.length + AUTH_TAG_LENGTH) {
                throw new Exception("Unexpected encrypted length: " + encryptedPayload.length + " (expected " + (payloadPlain.length + AUTH_TAG_LENGTH) + ")");
            }
    
            // 11. Check total size
            int actualPayloadLenSize = getVarIntSize(payloadLength);
            int actualTotalSize = headerBaseSize + actualPayloadLenSize + payloadLength;
            if (actualTotalSize < MIN_INITIAL_SIZE) {
                int additionalPadding = MIN_INITIAL_SIZE - actualTotalSize;
                System_out_println("Correction: actualSize=" + actualTotalSize + ", adding " + additionalPadding + " padding");
    
                // Add additional padding to payloadPlain
                ByteArrayOutputStream newPayloadPlain = new ByteArrayOutputStream();
                newPayloadPlain.write(payloadPlain);
                for (int i = 0; i < additionalPadding; i++) {
                    newPayloadPlain.write(0x00);
                }
                payloadPlain = newPayloadPlain.toByteArray();
    
                // Recalculate payload_length
                payloadLength = pnLength + payloadPlain.length + AUTH_TAG_LENGTH;
    
                // Rebuild header
                fullHeader = new ByteArrayOutputStream();
                fullHeader.write(headerBase.toByteArray());
                writeVariableLength(payloadLength, fullHeader);
                unprotectedHeader = fullHeader.toByteArray();
    
                // Rebuild AAD
                aadStream = new ByteArrayOutputStream();
                aadStream.write(unprotectedHeader);
                aadStream.write(pnBytes);
                aad = aadStream.toByteArray();
    
                // Re-encrypt
                encryptedPayload = encryptAes128Gcm(serverKey, nonce, payloadPlain, aad);
    
                if (encryptedPayload == null) {
                    throw new Exception("Encryption failed");
                }
            }
    
            System_out_println("Final payloadLength=" + payloadLength + ", encryptedPayload.length=" + encryptedPayload.length + ", totalPacketSize=" + (unprotectedHeader.length + pnLength + payloadPlain.length + AUTH_TAG_LENGTH));
    
            // 12. Assemble unprotected payload for HP sample
            ByteArrayOutputStream unprotectedPayloadStream = new ByteArrayOutputStream();
            unprotectedPayloadStream.write(pnBytes);
            unprotectedPayloadStream.write(encryptedPayload);
            byte[] unprotectedPayload = unprotectedPayloadStream.toByteArray();
    
            // 13. Header Protection
            if (unprotectedPayload.length < 20) {
                throw new Exception("Payload too short for sample");
            }
            byte[] sample = Arrays.copyOfRange(unprotectedPayload, 4, 20);
            byte[] mask = generateAes128Ecb(serverHp, sample);
    
            // Mask first byte
            byte[] protectedHeader = unprotectedHeader.clone();
            protectedHeader[0] ^= (mask[0] & 0x0F);
    
            // Mask PN
            byte[] protectedPn = pnBytes.clone();
            for (int i = 0; i < pnLength; i++) {
                protectedPn[i] ^= (byte) mask[i + 1];
            }
    
            // 14. Assemble and send
            ByteBuffer packetBuf = ByteBuffer.allocate(protectedHeader.length + protectedPn.length + encryptedPayload.length);
            packetBuf.put(protectedHeader);
            packetBuf.put(protectedPn);
            packetBuf.put(encryptedPayload);
            packetBuf.flip();
    
            channel.send(packetBuf, clientAddress);
            System_out_println("? CONNECTION_CLOSE sent! Size: " + packetBuf.limit() + " bytes");
    
            // Decryption test
            packetBuf.rewind(); // Reset for testing
            testDecryptResponse(packetBuf, packetNumber, pnLength, serverKey, serverIv, serverHp);
    
        } catch (Exception e) {
            System_out_println("? Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void testDecryptResponse(ByteBuffer packetBuffer, long expectedPn, int expectedPnLength, byte[] key, byte[] iv, byte[] hpKey) throws Exception {    
        packetBuffer.position(0);
        byte firstByte = packetBuffer.get();  
        byte[] version = new byte[4];
        packetBuffer.get(version);
        int dcidLen = packetBuffer.get() & 0xFF;
        byte[] dcid = new byte[dcidLen];
        packetBuffer.get(dcid);
        int scidLen = packetBuffer.get() & 0xFF;
        byte[] scid = new byte[scidLen];
        packetBuffer.get(scid);
        System_out_println(" Size previous scid: " + packetBuffer.position());
    
        VarLenResult tokenLenRes = readVariableLength(packetBuffer);
        byte[] token = new byte[(int) tokenLenRes.value];
        if (token.length > 0) { packetBuffer.get(token); }
        System_out_println(" Size previous token: " + packetBuffer.position());    
    
        VarLenResult payloadLenRes = readVariableLength(packetBuffer);
        int payloadLength = (int) payloadLenRes.value;
    
        // Position at start of protected payload
        int payloadPosition = packetBuffer.position();
        System_out_println("\n?? Testing decryption of sent packet...size after var len: " + payloadPosition);
        
        // Sample from protected payload[4:20]
        packetBuffer.position(payloadPosition + 4);
        byte[] sample = new byte[16];  
        if (packetBuffer.remaining() >= 16) {
            packetBuffer.get(sample);
        } else {
            throw new Exception("Payload too short for sample");
        }
        System_out_println(" Sample test (bytes 4-20): " + bytesToHex(sample));
         
        byte[] mask = generateAes128Ecb(hpKey, sample);
        System_out_println(mask.length + " Mask test (first 5): " + bytesToHex(mask)); 
    
        byte unmaskedFirstByte = (byte) (firstByte ^ (mask[0] & 0x0f));
        int derivedPnLength = (unmaskedFirstByte & 0x03) + 1;
        System_out_println(" First byte test: 0x" + String.format("%02X", firstByte) + " -> 0x" + String.format("%02X", unmaskedFirstByte));     
        System_out_println(" Protected packet number length test: " + derivedPnLength + " bytes");   
    
        // Unmask PN field
        packetBuffer.position(payloadPosition);
        byte[] protectedPnField = new byte[derivedPnLength];
        packetBuffer.get(protectedPnField);
        payloadPosition = packetBuffer.position();
        System_out_println("  Encrypted pn-holder len test: " + protectedPnField.length + " follow position: " + packetBuffer.position());
    
        byte[] unmaskedPnField = new byte[derivedPnLength];
        for (int i = 0; i < derivedPnLength; i++) {
            unmaskedPnField[i] = (byte) (protectedPnField[i] ^ mask[i + 1]);
        }
        long derivedPn = bytesToLong(unmaskedPnField);

        System_out_println(" Packet number test: " + derivedPn);  
   
        // Build AAD = unmasked first byte + rest of header + length + unmasked PN      
        byte[] aad = new byte[payloadPosition];
        packetBuffer.position(0);
        packetBuffer.get(aad);
        packetBuffer.position(payloadPosition);
        aad[0] = unmaskedFirstByte;
        System.arraycopy(unmaskedPnField, 0, aad, aad.length - derivedPnLength, derivedPnLength);
    
        // Ciphertext + tag = the remaining payload after PN
        int ciphertextLength = payloadLength - derivedPnLength;
        byte[] ciphertextWithTag = new byte[ciphertextLength];
        packetBuffer.get(ciphertextWithTag);          
                                                                                       
        // Decrypt
        byte[] nonce = computeNonce(iv, derivedPn, derivedPnLength);
        System_out_println(" Nonce test: " + bytesToHex(nonce) + " > cipher with tag len: " + ciphertextWithTag.length + " > aad len: " + aad.length);
        byte[] decryptedFrames = decryptAes128Gcm(key, nonce, ciphertextWithTag, aad);
    
        if (decryptedFrames != null) {
            System_out_println(" ? Test decryption successful! Derived PN: " + derivedPn + " (expected: " + expectedPn + "), pnLength: " + derivedPnLength + " (expected: " + expectedPnLength + ")");
            System_out_println(" Decrypted frames length: " + decryptedFrames.length);
            System_out_println(" Decrypted frames (hex first 20): " + bytesToHex(decryptedFrames, 20) + "\r\n");
        } else {
            System_out_println(" ? Test decryption failed!\r\n");
        }
    }
          
    private byte[] encryptAes128Gcm(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            System_out_println(" ? GCM encryption error: " + e.getMessage());
            return null;
        }
    }
    
    public static void writeVariableLength(long value, OutputStream os) throws IOException {
        if (value < 0) {
            throw new IllegalArgumentException(" Negative values not supported: " + value);
        }
    
        if (value <= 0x3F) {                      // 63, 1
            os.write((byte) (value & 0x3F));
        } else if (value <= 0x3FFF) {             // 16383, 2 
            os.write((byte) (((value >> 8) & 0x3F) | 0x40));
            os.write((byte) (value & 0xFF));
        } else if (value <= 0x3FFFFFFF) {         // 1073741823, 4 
            os.write((byte) (((int) (value >> 24) & 0x3F) | 0x80));
            os.write((byte) ((value >> 16) & 0xFF));
            os.write((byte) ((value >> 8) & 0xFF));
            os.write((byte) (value & 0xFF));
        } else if (value <= 0x3FFFFFFFFFFFFFFFL) { // 2^62 - 1, 8 
            os.write((byte) ((int) ((value >> 56) & 0x3F) | 0xC0));
            os.write((byte) ((value >> 48) & 0xFF));
            os.write((byte) ((value >> 40) & 0xFF));
            os.write((byte) ((value >> 32) & 0xFF));
            os.write((byte) ((value >> 24) & 0xFF));
            os.write((byte) ((value >> 16) & 0xFF));
            os.write((byte) ((value >> 8) & 0xFF));
            os.write((byte) (value & 0xFF));
        } else {
            throw new IllegalArgumentException(" To big value for this format: " + value);
        }
    }  

    private byte[] longToBytes(long value, int length) {
        byte[] bytes = new byte[length];
        for (int i = length - 1; i >= 0; i--) {
            bytes[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return bytes;
    }
  
    private void analyzeTlsHandshake(ConnectionState state, byte[] tlsData) {
        if (tlsData.length < 1) {
            System_out_println(" ? Data zero");
            return;
        }
        // TLS Handshake type (1 = ClientHello)
        byte handshakeType = tlsData[0];
       
        if (handshakeType != 0x01) {
            System_out_println(" Not a ClientHello (type: 0x" + String.format("%02X", handshakeType) + ")");
            //System_out_println(" Expected 0x01 for ClientHello");
            return;
        }
   
        if (tlsData.length < 4) {
            System_out_println(" ? TLS Data too short A: " + tlsData.length);
            return;
        }
   
        //System_out_println(" Found ClientHello\r\n" + new String(tlsData));
       
        int handshakeLength = ((tlsData[1] & 0xFF) << 16) |
                             ((tlsData[2] & 0xFF) << 8) |
                             (tlsData[3] & 0xFF);
       
        System_out_println(" Handshake length: " + handshakeLength + " bytes");
       
        if (tlsData.length < 6) {
            System_out_println(" ? TLS Data too short B: " + tlsData.length);
            return;
        }
           
        if (tlsData.length < handshakeLength + 4) {
            System_out_println(" ? TLS data shorter than handshake length");
            return;
        }
       
        // TLS version
        int tlsVersion = ((tlsData[4] & 0xFF) << 8) | (tlsData[5] & 0xFF);
        String tlsVersionStr = String.format("0x%04X", tlsVersion);
        String tlsVersionName = "";
        if (tlsVersion == 0x0303) {
            tlsVersionName = " (TLS 1.2)";
        } else if (tlsVersion == 0x0304) {
            tlsVersionName = " (TLS 1.3)";
        }
       
        if (tlsData.length < 39) {
            System_out_println(" ? TLS data too short: " + tlsData.length);
            return;
        }
   
        byte[] random = Arrays.copyOfRange(tlsData, 6, 38);
       
        // Session ID length
        int sessionIdLength = tlsData[38] & 0xFF;
        int cursor = 39;
       
        // Session ID
        byte[] sessionId = new byte[0];
        if (sessionIdLength > 0 && cursor + sessionIdLength <= tlsData.length) {
            sessionId = Arrays.copyOfRange(tlsData, cursor, cursor + sessionIdLength);
        }
        cursor += sessionIdLength;
       
        // Cipher suites length
        if (cursor + 2 > tlsData.length) {
            System_out_println(" ? Not enough data for cipher suites length");
            return;
        }
       
        int cipherSuitesLength = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
        cursor += 2;
       
        // Cipher suites
        int numCiphers = cipherSuitesLength / 2;
        List<String> cipherSuites = new ArrayList<String>();
        if (cursor + cipherSuitesLength <= tlsData.length) {
            for (int i = 0; i < numCiphers; i++) {
                int cipherCode = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
                cipherSuites.add(String.format("0x%04X", cipherCode));
                cursor += 2;
            }
        }
       
        // Compression methods length
        if (cursor >= tlsData.length) {
            System_out_println(" ? Not enough data for compression methods length");
            return;
        }
       
        int compressionLength = tlsData[cursor] & 0xFF;
        cursor += 1 + compressionLength; //
       
        // Extensions length
        if (cursor + 2 > tlsData.length) {
            System_out_println(" ? Not enough data for extensions length");
            return;
        }
       
        int extensionsLength = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
        cursor += 2;
       
        System_out_println("\n?? TLS 1.3 CLIENT HELLO DETECTED!");
        System_out_println("=================================");
        System_out_println("Handshake Type: ClientHello (0x01)");
        System_out_println("TLS Version: " + tlsVersionStr + tlsVersionName);
        System_out_println("Random (first 8 bytes): " + bytesToHex(random, 8));
        System_out_println("Session ID: " + (sessionIdLength > 0 ? bytesToHex(sessionId, 8) + "..." : "empty"));
        System_out_println("Cipher Suites (" + numCiphers + "):");
        for (int i = 0; i < Math.min(5, cipherSuites.size()); i++) {
            System_out_println(" - " + cipherSuites.get(i));
        }
        if (cipherSuites.size() > 5) {
            System_out_println(" ... and " + (cipherSuites.size() - 5) + " more");
        }
        System_out_println("Extensions length: " + extensionsLength + " bytes");
       
        if (cursor + extensionsLength <= tlsData.length && extensionsLength > 0) {
            analyzeTlsExtensions(state, tlsData, cursor, extensionsLength);
        }
    }
   
   
    private void analyzeTlsExtensions(ConnectionState state, byte[] tlsData, int start, int length) {
        System_out_println("\nTLS Extensions:");
       
        int cursor = start;
        int end = start + length;
        int extensionCount = 0;
        boolean isReadable;
    
        while (cursor < end && cursor + 4 <= tlsData.length) {
            extensionCount++;
           
            // Extension type
            int extensionType = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
            cursor += 2;
           
            // Extension length
            int extensionLength = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
            cursor += 2;
           
            String extensionName = getExtensionName(extensionType);
            System_out_println(String.format(" %2d. 0x%04X", extensionCount, extensionType) +
                             ": " + extensionName + " (" + extensionLength + " bytes)");
            isReadable = cursor + extensionLength <= tlsData.length;

            if (extensionType == 0x0000) { // server_name
                if(isReadable) { analyzeServerNameExtension(tlsData, cursor, extensionLength); }
            }
            else if (extensionType == 0x000A) { // supported_groups
                if(isReadable) { analyzeSupportedGroupsExtension(tlsData, cursor, extensionLength); }
            }
            else if (extensionType == 0x000D) { // signature_algorithms
                if(isReadable) { analyzeSignatureAlgorithmsExtension(tlsData, cursor, extensionLength); }
            }
            else if (extensionType == 0x0010) { // ALPN
                if(isReadable) { analyzeAlpnExtension(tlsData, cursor, extensionLength); }
            }
            else if (extensionType == 0x002B) { // supported_versions
                if(isReadable) { analyzeSupportedVersionsExtension(tlsData, cursor, extensionLength); }
            }
            else if (extensionType == 0x002D) { // psk_key_exchange_modes
                if(isReadable) { analyzePskKeyExchangeModesExtension(tlsData, cursor, extensionLength); }
            }
            else if (extensionType == 0x0033) { // key_share
                if(isReadable) { analyzeKeyShareExtension(tlsData, cursor, extensionLength); }
            }
            else if (extensionType == 0x0039 || extensionType == 0x4469) { // quic_transport_parameters
                //System_out_println(" QUIC Transport Parameters extension (" + 
                //                   String.format("0x%04X", extensionType) + ")");
                
                // Now parse the parameters blob
                if(isReadable) { parseQuicTransportParameters(tlsData, cursor, extensionLength, state); }
            }
            else if (extensionType == 0x002C) { 
                state.isZeroRTT = true;
                System_out_println(" QUIC 0-RTT extension");
            }          
            cursor += extensionLength;
        }
    }
  
    private void parseQuicTransportParameters(byte[] data, int start, int length, ConnectionState state) {
        int offset = start;
        int end = start + length;
    
        System_out_println("   Parsing QUIC Transport Parameters (" + length + " bytes):");
    
        while (offset < end) {
            // Read parameter ID (varint)
            VarLenResult idResult = readVariableLength(data, offset);
            if (idResult.size == 0) break;
            offset += idResult.size;
            long paramId = idResult.value;
    
            // Read parameter length (varint)
            VarLenResult lenResult = readVariableLength(data, offset);
            if (lenResult.size == 0) break;
            offset += lenResult.size;
            long paramLen = lenResult.value;
    
            if (offset + paramLen > end) {
                System_out_println("     ? Truncated parameter 0x" + Long.toHexString(paramId));
                break;
            }
    
            String paramName = getTransportParamName(paramId);
            System_out_println(String.format("     Param 0x%04X: %s (length %d)", paramId, paramName, paramLen));
    
            if ((int)paramId == 0x11) { // version_information
                parseVersionInformation(data, offset, (int) paramLen, state);
            }
    
            offset += paramLen;
        }
    }
  
    private void parseVersionInformation(byte[] data, int start, int length, ConnectionState state) {
        if (length < 4 || length % 4 != 0) {
            System_out_println("     ? Invalid version_information length: " + length);
            return;
        }
    
        System_out_println("     === version_information (RFC 9368) ===");
    
        int offset = start;
        int numVersions = length / 4;
    
        // First 4 bytes: Chosen Version
        int chosen = ((data[offset] & 0xFF) << 24) |
                     ((data[offset+1] & 0xFF) << 16) |
                     ((data[offset+2] & 0xFF) << 8) |
                     (data[offset+3] & 0xFF);
        offset += 4;
    
        String chosenHex = String.format("0x%08X", chosen);
        String chosenName = getQuicVersionName(chosen);
    
        System_out_println("       Chosen Version : " + chosenHex + "  " + chosenName);
    
        // Remaining versions: Available Versions list
        System_out_println("       Available Versions (" + (numVersions - 1) + "):");
        for (int i = 1; i < numVersions; i++) {
            int ver = ((data[offset] & 0xFF) << 24) |
                      ((data[offset+1] & 0xFF) << 16) |
                      ((data[offset+2] & 0xFF) << 8) |
                      (data[offset+3] & 0xFF);
            offset += 4;
    
            String verHex = String.format("0x%08X", ver);
            String verName = getQuicVersionName(ver);
    
            System_out_println("         " + verHex + "  " + verName);
     
            // if (ver == QUIC_VERSION_2_VALUE) state.supportsQuicV2 = true;
        }
    }  

    private String getQuicVersionName(int version) {
        if (version == 0x00000001) return "(QUICv1)";
        if (version == 0x6b3343cf) return "(QUICv2)";
        if (version == 0x00000000) return "(Version Negotiation)";
        return "";
    }  
  
    private String getTransportParamName(long id) {
        switch ((int) id) {
            case 0x00: return "original_destination_connection_id";
            case 0x01: return "max_idle_timeout";
            case 0x02: return "stateless_reset_token";
            case 0x03: return "max_udp_payload_size";
            case 0x04: return "initial_max_data";
            case 0x05: return "initial_max_stream_data_bidi_local";
            case 0x06: return "initial_max_stream_data_bidi_remote";
            case 0x07: return "initial_max_stream_data_uni";
            case 0x08: return "initial_max_streams_bidi";
            case 0x09: return "initial_max_streams_uni";
            case 0x0a: return "ack_delay_exponent";
            case 0x0b: return "max_ack_delay";
            case 0x0c: return "disable_active_migration";
            case 0x0d: return "preferred_address";
            case 0x0e: return "active_connection_id_limit";
            case 0x0f: return "initial_source_connection_id";
            case 0x10: return "retry_source_connection_id";
            case 0x11: return "version_information";
            case 0x12: return "max_datagram_frame_size";
            case 0x13: return "grease_quic_bit";
            default: return "unknown_" + Long.toHexString(id);
        }
    }  
      
    private void analyzeServerNameExtension(byte[] tlsData, int start, int length) {
        int cursor = start;
        if (cursor + 2 <= tlsData.length) {
            int serverNameListLength = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
            cursor += 2;
           
            if (cursor + 1 <= tlsData.length && serverNameListLength > 0) {
                int nameType = tlsData[cursor++] & 0xFF;
                if (cursor + 2 <= tlsData.length) {
                    int nameLength = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
                    cursor += 2;
                   
                    if (cursor + nameLength <= tlsData.length) {
                        String serverName = new String(tlsData, cursor, nameLength);
                        System_out_println(" Server Name: " + serverName + " (Type: " + nameType + ")");
                    }
                }
            }
        }
    }
   
    private void analyzeSupportedGroupsExtension(byte[] tlsData, int start, int length) {
        int cursor = start;
        if (cursor + 2 <= tlsData.length) {
            int groupsLength = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
            cursor += 2;
           
            String a = " Supported Groups: "; //System_out_print();
            int numGroups = groupsLength / 2;
            for (int i = 0; i < numGroups && cursor + 2 <= tlsData.length; i++) {
                int group = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
                String groupName = getGroupName(group);
                a += groupName + " "; //System_out_print(groupName + " ");
                cursor += 2;
            }
            System_out_println(a);
        }
    }
   
    private void analyzeSignatureAlgorithmsExtension(byte[] tlsData, int start, int length) {
        int cursor = start;
        if (cursor + 2 <= tlsData.length) {
            int sigAlgsLength = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
            cursor += 2;
           
            String a = " Signature Algorithms: "; //System_out_print();
            int numAlgs = sigAlgsLength / 2;
            for (int i = 0; i < numAlgs && cursor + 2 <= tlsData.length; i++) {
                int sigAlg = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
                a += String.format("0x%04X", sigAlg) + " "; //System_out_print();
                cursor += 2;
            }
            System_out_println(a);
        }
    }
   
    private void analyzeAlpnExtension(byte[] tlsData, int start, int length) {
        int cursor = start;
        if (cursor + 2 <= tlsData.length) {
            int alpnLength = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
            cursor += 2;
           
            int alpnStart = cursor;
            while (cursor < alpnStart + alpnLength && cursor < tlsData.length) {
                int protoLength = tlsData[cursor++] & 0xFF;
                if (cursor + protoLength <= tlsData.length) {
                    String protocol = new String(tlsData, cursor, protoLength);
                    System_out_println(" ALPN Protocol: " + protocol);
                    cursor += protoLength;
                }
            }
        }
    }
   
    private void analyzeSupportedVersionsExtension(byte[] tlsData, int start, int length) {
        int cursor = start;
        if (cursor + 1 <= tlsData.length) {
            int versionsLength = tlsData[cursor++] & 0xFF;
            String a = " Supported Versions: "; //System_out_print();
            for (int i = 0; i < versionsLength / 2 && cursor + 2 <= tlsData.length; i++) {
                int version = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
                String versionStr = String.format("0x%04X", version);
                if (version == 0x0304) {
                    versionStr += "(TLS1.3)";
                } else if (version == 0x0303) {
                    versionStr += "(TLS1.2)";
                }
                a += versionStr + " "; //System_out_print();
                cursor += 2;
            }
            System_out_println(a);
        }
    }
   
    private void analyzePskKeyExchangeModesExtension(byte[] tlsData, int start, int length) {
        int cursor = start;
        if (cursor + 1 <= tlsData.length) {
            int modesLength = tlsData[cursor++] & 0xFF;
            String a = " PSK Key Exchange Modes: "; //System_out_print();
            for (int i = 0; i < modesLength && cursor < tlsData.length; i++) {
                int mode = tlsData[cursor++] & 0xFF;
                a += String.format("0x%02X", mode) + " "; //System_out_print();
            }
            System_out_println(a);
        }
    }
   
    private void analyzeKeyShareExtension(byte[] tlsData, int start, int length) {
        int cursor = start;
        if (cursor + 2 <= tlsData.length) {
            int keyShareLength = ((tlsData[cursor] & 0xFF) << 8) | (tlsData[cursor + 1] & 0xFF);
            cursor += 2;
           
            System_out_println(" Key Share entries: " + (keyShareLength / 4) + " (approx)");
        }
    }
 
    private int skipAckFrame(byte[] data, int offset) {
        if (offset >= data.length) { return offset; }
       
        VarLenResult largestAcked = readVariableLength(data, offset);
        offset += largestAcked.size;
       
        VarLenResult ackDelay = readVariableLength(data, offset);
        offset += ackDelay.size;
       
        VarLenResult rangeCount = readVariableLength(data, offset);
        offset += rangeCount.size;
       
        VarLenResult firstRange = readVariableLength(data, offset);
        offset += firstRange.size;
       
        // ACK Ranges 
        for (long i = 0; i < rangeCount.value - 1 && offset < data.length; i++) {
            // Gap
            VarLenResult gap = readVariableLength(data, offset);
            offset += gap.size;
           
            // ACK Range Length
            VarLenResult rangeLen = readVariableLength(data, offset);
            offset += rangeLen.size;
        }
       
        return offset;
    }
   
    private int parseStreamFrame(byte[] data, int frameType, int offset) {
        if (offset >= data.length) { return offset; }
    
        VarLenResult streamId = readVariableLength(data, offset);
        offset += streamId.size;
        
        if ((frameType & 0x04) != 0) {
            VarLenResult offsetIn = readVariableLength(data, offset);
            offset += offsetIn.size;
        }
        
        if ((frameType & 0x02) != 0) {
            VarLenResult length = readVariableLength(data, offset);
            offset += length.size;  
      
            if (offset + length.value > data.length || (int)length.value < 0) { return offset; }
            byte[] stream = new byte[(int)length.value];
            System.arraycopy(data, offset, stream, 0, stream.length);
      
            offset += (int)length.value; 
            //buffer.get(data);
            System_out_println("STREAM Frame - ID: " + streamId.value + ", Data: " + new String(stream));
        } else {
          int length = data.length - offset;
          if(length > 0) {
            byte[] stream = new byte[length];
            System.arraycopy(data, offset, stream, 0, stream.length);
      
            offset += length; 
            //buffer.get(data);
            System_out_println("STREAM rest Frame - ID: " + streamId.value + ", Data: " + new String(stream));        
          }
        }
    
        return offset;    
    }
  
    private int skipConnectionCloseFrame(byte[] data, int offset, byte frameType) {
        if (offset >= data.length) { return offset; }
       
        // Error Code
        VarLenResult errorCode = readVariableLength(data, offset);
        offset += errorCode.size;
    
        // Frame Type
        if (frameType == 0x1c) {
            VarLenResult frameTypeError = readVariableLength(data, offset);
            offset += frameTypeError.size;
        }
       
        // Reason Phrase Length
        VarLenResult reasonLength = readVariableLength(data, offset);
        offset += reasonLength.size + (int)reasonLength.value;
       
        return offset;
    }
   
    private String getExtensionName(int type) {
        switch (type) {
            case 0x0000: return "server_name";
            case 0x000A: return "supported_groups";
            case 0x000B: return "ec_point_formats";
            case 0x000D: return "signature_algorithms";
            case 0x000F: return "heartbeat";
            case 0x0010: return "ALPN";
            case 0x0017: return "extended_master_secret";
            case 0x001B: return "supported_versions";
            case 0x001D: return "ticket_early_data";
            case 0x001E: return "cookie";
            case 0x001F: return "psk";
            case 0x0020: return "early_data";
            case 0x0022: return "delegated_credentials";
            case 0x0021: return "certificate_authorities";
            case 0x0029: return "pre_shared_key";
            case 0x002A: return "key_share";
            case 0x002B: return "supported_versions";
            case 0x002D: return "psk_key_exchange_modes";
            case 0x0033: return "key_share";
            case 0x0039: return "quic_transport_parameters";
            case 0x003C: return "session_ticket";
            case 0x003D: return "key_share";
            case 0x4469: return "quic_transport_parameters";
            default: return "unknown_" + String.format("%04X", type);
        }
    }
    private String getGroupName(int group) {
        switch (group) {
            case 0x001D: return "X25519";
            case 0x0017: return "secp256r1";
            case 0x0018: return "secp384r1";
            case 0x0019: return "secp521r1";
            case 0x001E: return "X448";
            case 0x0100: return "FFDHE2048";
            case 0x0101: return "FFDHE3072";
            case 0x0102: return "FFDHE4096";
            case 0x0103: return "FFDHE6144";
            case 0x0104: return "FFDHE8192";
            default: return String.format("0x%04X", group);
        }
    }
    private void cleanup() throws IOException {
        if (selector != null) selector.close();
        if (channel != null) channel.close();
    }
  
    private void System_out_println() {
      if(!printSelf) { System.out.println(); toPrint(""); return; }
      outp += "\r\n";
    }
 
    private void System_out_println(String a) {
      if(!printSelf) { System.out.println(a); toPrint(a); return; }
      outp += a + "\r\n";
    }
 
    private void System_out_print(String a) {
      if(!printSelf) { System.out.print(a); toPrint(a); return; }
      outp += a;
    }
 
    private void System_out_print() { }
  
    private String getInLabel(int version, boolean client) {
        if (version == 2) {
            return client ? "quicv2 client in" : "quicv2 server in";
        } else {
            return client ? "client in" : "server in";
        }
    }

    private String getKeyLabel(int version) {
        return version == 2 ? "quicv2 key" : "quic key";
    }

    private String getIvLabel(int version) {
        return version == 2 ? "quicv2 iv" : "quic iv";
    }

    private String getHpLabel(int version) {
        return version == 2 ? "quicv2 hp" : "quic hp";
    }

    private static class QuicPacket {
        //byte[] rawData;
        boolean isLongHeader;
        boolean isInitial;
        byte type;
        byte[] version;
        int isVersion;
        byte[] destinationConnectionId;
        byte[] sourceConnectionId;
        byte[] token = new byte[0];
        int payloadLength;
        //byte[] encryptedPayload;
        //byte[] header;
        //int pnLengthFromHeader;
        byte firstByte;
        long packetNumber;
    }
  
    private static class DecryptedInitialPacket {
        QuicPacket packet;
        byte[] decryptedPayload;
        byte[] clientKey;
        byte[] clientIv;
    }
  
    private static class VarLenResult {
        final long value;
        final int size;
        VarLenResult(long value, int size) {
            this.value = value;
            this.size = size;
        }
    }

    private static class ByteArrayWrapper {
        private final byte[] data;

        public ByteArrayWrapper(byte[] data) {
            this.data = data != null ? data.clone() : null;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ByteArrayWrapper that = (ByteArrayWrapper) o;
            return Arrays.equals(data, that.data);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(data);
        }
    }

    private static class ConnectionState {
        TreeMap<Long, byte[]> cryptoChunks = new TreeMap<Long, byte[]>();
        long largestPacketNumber = 0;
        long fullCryptoLen = 0;
        long partialCryptoLen = 0;
        long packetNumberSent = 0;
        byte[] lastDCID = null;
        ByteArrayWrapper subsequentSCID = null;
        boolean isZeroRTT = false;  
        //boolean helloExtracted = false;
    }
    
   protected static Method getMethod(Class<?> userClass, String m, Class<?> b) throws Exception {
     return userClass.getMethod(m, b);
   }

   public static Method getMethod(Class<?> userClass, String m, Class<?> b[]) throws Exception {
     return userClass.getMethod(m, b);
   }
  
   private void toPrintOld(String t) {
     try {
       getMethod(Class.forName("com.System_out"), "println", new Class<?>[] { String.class }).invoke(null, new Object[] { t });
     } catch(Exception as) { 
     }
   }       
  
   private void toPrint(String hcbS) {
     File file = tPu;
     hcbS += "\r\n";
     byte[] hcb;                                                          
     try { hcb = hcbS.getBytes("UTF-8"); } catch(Exception sd) { return; }
  
     FileOutputStream afile = null;

     synchronized(logRdpMainSync) {
       try { 
         if(!file.exists()) {            
           try { file.createNewFile(); } catch(Exception da) { System.out.println("File creating error: " + da.getMessage()); }
         }
         afile = new FileOutputStream(file, true);
         afile.write(hcb, 0, hcb.length);
         afile.close();
         afile = null;
       } catch(Exception sd) { 
         System.out.println("File error: " + sd.getMessage());
       } finally {
         if(afile != null) { try { afile.close(); afile = null; } catch(Exception edj) { } }
       }
     }
     if(afile != null) { try { afile.close(); } catch(Exception edj) { } }
   }

    public static String setPathToKey() {
        String pathtokey = "";
        String fsep = File.separator;
        try {
          String defcp = System.getProperty("file.encoding");
          System.setProperty("file.encoding", "UTF-8");
          String myf = URLDecoder.decode(MinimalQuicServer.class.getClassLoader().getResource("META-INF/MANIFEST.MF").getFile(), "UTF-8");
          System.setProperty("file.encoding", defcp);
          return (new File(myf.substring(5, myf.lastIndexOf("!"))).getParent().toString()) + fsep;
          //com.System_out.println("main: " + JWIOServer.mypath);
        } catch(Exception e) { 
        }
        return pathtokey; 
    }
 
}
