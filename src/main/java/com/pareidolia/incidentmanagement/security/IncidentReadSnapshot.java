package com.pareidolia.incidentmanagement.security;

import jakarta.persistence.EntityManager;
import java.util.function.Supplier;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Materialize DTOs/bytes/scalar report rows here; never return a stream or lazy entity. */
@Component
public class IncidentReadSnapshot {
    private final IncidentSecurityGate gate;private final EntityManager em;private final TransactionTemplate transaction;
    public IncidentReadSnapshot(IncidentSecurityGate gate,EntityManager em,PlatformTransactionManager manager){
        this.gate=gate;this.em=em;transaction=new TransactionTemplate(manager);
        transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        transaction.setReadOnly(false);transaction.setTimeout(15);
    }
    public <T> T read(Supplier<T> work){
        if(gate.held())return work.get(); // Nested attachment/detail checks share the same snapshot or writer.
        return transaction.execute(status->{gate.read();em.clear();return work.get();});
    }
}
