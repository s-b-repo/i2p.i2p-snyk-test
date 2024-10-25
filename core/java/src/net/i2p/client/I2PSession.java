package net.i2p.client;

import java.io.InputStream;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import net.i2p.data.*;

public interface I2PSession {

    // Constants
    int PORT_ANY = 0;
    int PORT_UNSPECIFIED = 0;
    int PROTO_ANY = 0;
    int PROTO_UNSPECIFIED = 0;
    int PROTO_STREAMING = 6;
    int PROTO_DATAGRAM = 17;
    int PROTO_DATAGRAM_RAW = 18;

    // Asynchronous Message Sending
    CompletableFuture<Boolean> sendMessageAsync(Destination dest, byte[] payload, SendMessageOptions options);

    // Synchronous Message Sending (backward-compatible, streamlined)
    boolean sendMessage(Destination dest, byte[] payload, SendMessageOptions options) throws I2PSessionException;

    // Message Receiving
    byte[] receiveMessage(int msgId) throws I2PSessionException;
    void reportAbuse(int msgId, int severity) throws I2PSessionException;

    // Session Management
    void connect(int timeoutMs) throws I2PSessionException;
    void destroySession() throws I2PSessionException;
    boolean isClosed();

    // Subsession Management
    I2PSession addSubsession(InputStream privateKeyStream, Properties opts) throws I2PSessionException;
    void removeSubsession(I2PSession session);
    List<I2PSession> getSubsessions();

    // Key and Destination Access
    Destination getMyDestination();
    PrivateKey getDecryptionKey();
    SigningPrivateKey getPrivateKey();
    boolean isOffline();
    long getOfflineExpiration();
    Signature getOfflineSignature();
    SigningPublicKey getTransientSigningPublicKey();

    // Destination Lookup with Caching Support
    Destination lookupDest(Hash h, long maxWait) throws I2PSessionException;
    Destination lookupDest(String name, long maxWait) throws I2PSessionException;
    LookupResult lookupDest2(String name, long maxWait) throws I2PSessionException;

    // Options and Bandwidth
    void updateOptions(Properties options);
    int[] bandwidthLimits() throws I2PSessionException;

    // Blinding Information
    void sendBlindingInfo(BlindData bd) throws I2PSessionException;

    // Version Information
    String getRouterVersion();

    // Listener Management with Secure Removal
    void setSessionListener(I2PSessionListener lsnr, int timeoutMs);
    void addSessionListener(I2PSessionListener lsnr, int proto, int port);
    void addMuxedSessionListener(I2PSessionMuxedListener l, int proto, int port);
    void removeListener(int proto, int port);
}
