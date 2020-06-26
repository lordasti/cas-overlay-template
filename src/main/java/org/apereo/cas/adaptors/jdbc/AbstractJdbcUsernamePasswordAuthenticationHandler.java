package org.apereo.cas.adaptors.jdbc;

import javax.sql.*;

import org.apereo.cas.authentication.handler.support.*;
import org.apereo.cas.authentication.principal.*;
import org.apereo.cas.services.*;
import org.springframework.jdbc.core.*;
import org.springframework.jdbc.core.namedparam.*;

public abstract class AbstractJdbcUsernamePasswordAuthenticationHandler
        extends AbstractUsernamePasswordAuthenticationHandler {

    private final JdbcTemplate jdbcTemplate;

    private final NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    private final DataSource dataSource;

    public AbstractJdbcUsernamePasswordAuthenticationHandler(final String name, final ServicesManager servicesManager,
            final PrincipalFactory principalFactory, final Integer order, final DataSource dataSource) {
        super(name, servicesManager, principalFactory, order);
        this.dataSource = dataSource;
        this.jdbcTemplate = new JdbcTemplate(dataSource);
        this.namedParameterJdbcTemplate = new NamedParameterJdbcTemplate(this.jdbcTemplate);
    }

    /**
     * Method to return the jdbcTemplate.
     *
     * @return a fully created JdbcTemplate.
     */
    protected JdbcTemplate getJdbcTemplate() {
        return this.jdbcTemplate;
    }

    protected NamedParameterJdbcTemplate getNamedJdbcTemplate() {
        return this.namedParameterJdbcTemplate;
    }

    protected DataSource getDataSource() {
        return this.dataSource;
    }
}
