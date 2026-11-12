package com.pareidolia.incidentmanagement.security;

import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.assertj.core.api.Assertions.assertThat;

class IncidentStartupBoundsChecksTests {
    HikariDataSource source; JdbcTemplate jdbc;
    @BeforeEach void setup() {
        source=new HikariDataSource(); source.setConnectionTimeout(5000); source.setValidationTimeout(1000);
        source.setJdbcUrl("jdbc:mysql://127.0.0.1:3306/synthetic?connectTimeout=5000&socketTimeout=10000");
        jdbc=new JdbcTemplate(source); jdbc.setQueryTimeout(5);
    }
    @Test void boundedConfigurationIsPreliminaryOnly() {
        assertThat(IncidentStartupBoundsChecks.inspect(source,jdbc,10000)).isEqualTo(IncidentStartupBoundsChecks.Result.CONFIGURED_FOR_FURTHER_CHECKS);
    }
    @Test void missingOrAmbiguousDriverTimeoutIsRejected() {
        source.setJdbcUrl("jdbc:mysql://127.0.0.1:3306/synthetic?connectTimeout=5000");
        assertThat(IncidentStartupBoundsChecks.inspect(source,jdbc,10000)).isEqualTo(IncidentStartupBoundsChecks.Result.UNSAFE_CONFIGURATION);
        source.setJdbcUrl("jdbc:mysql://127.0.0.1:3306/synthetic?connectTimeout=5000&socketTimeout=10000&socketTimeout=0");
        assertThat(IncidentStartupBoundsChecks.inspect(source,jdbc,10000)).isEqualTo(IncidentStartupBoundsChecks.Result.UNSAFE_CONFIGURATION);
    }
    @Test void driverOverridesAndUnboundedPoolOrQueryAreRejected() {
        source.addDataSourceProperty("socketTimeout","0");
        assertThat(IncidentStartupBoundsChecks.inspect(source,jdbc,10000)).isEqualTo(IncidentStartupBoundsChecks.Result.UNSAFE_CONFIGURATION);
        source.getDataSourceProperties().remove("socketTimeout"); source.setConnectionTimeout(30000);
        assertThat(IncidentStartupBoundsChecks.inspect(source,jdbc,10000)).isEqualTo(IncidentStartupBoundsChecks.Result.UNSAFE_CONFIGURATION);
        source.setConnectionTimeout(5000); jdbc.setQueryTimeout(0);
        assertThat(IncidentStartupBoundsChecks.inspect(source,jdbc,10000)).isEqualTo(IncidentStartupBoundsChecks.Result.UNSAFE_CONFIGURATION);
    }
    @Test void invalidOverallDeadlineIsRejected() {
        assertThat(IncidentStartupBoundsChecks.inspect(source,jdbc,0)).isEqualTo(IncidentStartupBoundsChecks.Result.UNSAFE_CONFIGURATION);
        assertThat(IncidentStartupBoundsChecks.inspect(source,jdbc,30001)).isEqualTo(IncidentStartupBoundsChecks.Result.UNSAFE_CONFIGURATION);
        assertThat(IncidentStartupBoundsChecks.inspect(source,jdbc,2000)).isEqualTo(IncidentStartupBoundsChecks.Result.UNSAFE_CONFIGURATION);
    }
}
