package org.apereo.cas.adaptors.jdbc;

import java.security.*;
import java.util.*;

import javax.security.auth.login.*;
import javax.sql.*;

import org.apereo.cas.authentication.*;
import org.apereo.cas.authentication.principal.*;
import org.apereo.cas.services.*;
import org.slf4j.*;

import es.aytos.arquitectura.comun.util.*;
import es.aytos.arquitectura.security.handler.*;

public class QueryAndEncodeDatabaseAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    protected String algorithmName;

    protected String sql;

    protected String passwordFieldName = "password";

    protected String saltFieldName = "salt";

    protected String expiredFieldName;

    protected String disabledFieldName;

    protected String numberOfIterationsFieldName;

    protected long numberOfIterations;

    protected String staticSalt;

    public QueryAndEncodeDatabaseAuthenticationHandler(final String name, final ServicesManager servicesManager,
            final PrincipalFactory principalFactory, final Integer order, final DataSource dataSource,
            final String algorithmName, final String sql, final String passwordFieldName, final String saltFieldName,
            final String expiredFieldName, final String disabledFieldName, final String numberOfIterationsFieldName,
            final long numberOfIterations, final String staticSalt) {
        super(name, servicesManager, principalFactory, order, dataSource);
        this.algorithmName = algorithmName;
        this.sql = sql;
        this.passwordFieldName = passwordFieldName;
        this.saltFieldName = saltFieldName;
        this.expiredFieldName = expiredFieldName;
        this.disabledFieldName = disabledFieldName;
        this.numberOfIterationsFieldName = numberOfIterationsFieldName;
        this.numberOfIterations = numberOfIterations;
        this.staticSalt = staticSalt;
    }

    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(
            final UsernamePasswordCredential transformedCredential, final String originalPassword)
            throws GeneralSecurityException, PreventedException {

        /*
         * if (!this.activo) { this.log.debug("{},{},[{}]", UtilidadesHandler.getHostName(), "",
         * "Sistema de autenticación en base de datos desactivado"); return false; }
         */

        final String username = transformedCredential.getUsername();
        final String password = transformedCredential.getPassword();

        try {
            final Map<String, Object> passwordBD = this.getJdbcTemplate().queryForMap(this.sql, username);
            final boolean resultado = password.equals(this.obtenerPasswordSinEncriptar(passwordBD));

            if (resultado) {
                this.log.info("{},{},[{}]", UtilidadesHandler.getHostName(), username,
                        "Login de usuario " + username + " correcto en base de datos");
            } else {
                this.log.error("{},{},[{}]", UtilidadesHandler.getHostName(), username,
                        "Fallo de autenticación en base de datos para el usuario " + username);
                throw new FailedLoginException("Fallo de autenticación en base de datos para el usuario " + username);
            }

            /*
             * if (StringUtils.isNotBlank(this.expiredFieldName) && values.containsKey(this.expiredFieldName)) { final String
             * dbExpired = values.get(this.expiredFieldName).toString(); if (BooleanUtils.toBoolean(dbExpired) ||
             * "1".equals(dbExpired)) { throw new AccountPasswordMustChangeException("Password has expired"); } } if
             * (StringUtils.isNotBlank(this.disabledFieldName) && values.containsKey(this.disabledFieldName)) { final String
             * dbDisabled = values.get(this.disabledFieldName).toString(); if (BooleanUtils.toBoolean(dbDisabled) ||
             * "1".equals(dbDisabled)) { throw new AccountDisabledException("Account has been disabled"); } }
             */

            return this.createHandlerResult(transformedCredential, this.principalFactory.createPrincipal(username),
                    new ArrayList<>(0));
        } catch (final Exception e) {
            this.log.error("{},{},[{}]", UtilidadesHandler.getHostName(), username,
                    "Fallo de autenticación en base de datos para el usuario " + username + ". Exception: "
                            + e.getMessage());
            throw new FailedLoginException("Fallo de autenticación en base de datos para el usuario " + username);
        }
    }

    protected String obtenerPasswordSinEncriptar(final Map<String, Object> passwordBD) {
        final String passwordEncriptado = passwordBD.get("USU_PAS").toString();
        final int encriptacion = this.obtenerNivelDeEncriptacion(passwordBD);

        String resultado;
        switch (encriptacion) {
        case 2:
            resultado = Codificador.decodificar(passwordEncriptado, "THERMIDOR");
            break;
        case 1:
            resultado = Codificador.decodificarSinBase64(passwordEncriptado, "THERMIDOR");
            break;
        case 0:
        default:
            resultado = passwordEncriptado;
            break;
        }
        return resultado;
    }

    protected int obtenerNivelDeEncriptacion(final Map<String, Object> passwordBD) {
        return passwordBD.get("USU_ENC") == null ? 0 : Integer.parseInt(passwordBD.get("USU_ENC").toString());
    }

    public void setSql(final String sql) {
        this.sql = sql;
    }

}
