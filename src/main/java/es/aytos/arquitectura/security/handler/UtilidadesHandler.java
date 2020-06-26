package es.aytos.arquitectura.security.handler;

import java.net.*;

public class UtilidadesHandler {

    private UtilidadesHandler() {
        // clase de utilidad
    }

    public static String getHostName() {
        String hostName;
        try {
            hostName = InetAddress.getLocalHost().getHostName();
        } catch (final UnknownHostException e) {
            hostName = "UNKNOWN";
        }
        return hostName;
    }
}
