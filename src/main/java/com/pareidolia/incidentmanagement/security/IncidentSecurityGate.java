package com.pareidolia.incidentmanagement.security;

import jakarta.persistence.EntityManager;
import java.util.IdentityHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Global shared-read/exclusive-write gate. Must precede every account/incident lock. */
@Component
public class IncidentSecurityGate {
    private static final ThreadLocal<Map<Object,Boolean>> HELD=ThreadLocal.withInitial(IdentityHashMap::new);
    private final EntityManager em; private final boolean enabled;
    @org.springframework.beans.factory.annotation.Autowired
    public IncidentSecurityGate(EntityManager em,
            @Value("${app.incident-access.enabled:false}") boolean incidentAccessEnabled,
            @Value("${app.department-membership-admin.enabled:false}") boolean membershipAdminEnabled) {
        this(em, incidentAccessEnabled || membershipAdminEnabled);
    }

    IncidentSecurityGate(EntityManager em, boolean enabled) {
        this.em = em;
        this.enabled = enabled;
    }
    private Object transaction(){return TransactionSynchronizationManager.getResource(em.getEntityManagerFactory());}
    public boolean held(){return TransactionSynchronizationManager.isActualTransactionActive() && HELD.get().containsKey(transaction());}
    public String sharedClause(){
        String product=em.unwrap(org.hibernate.Session.class).doReturningWork(c->c.getMetaData().getDatabaseProductName());
        if(product.equalsIgnoreCase("MySQL"))return " for share";
        if(product.equalsIgnoreCase("H2"))return " for update"; // H2 conservatively serializes readers in tests.
        throw new IllegalStateException("Incident security gate requires verified MySQL or isolated H2.");
    }
    public void read(){if(enabled)acquire(false);}
    public void write(){if(enabled)acquire(true);}

    /** Legacy confidentiality checks must coordinate with guarded classification writers. */
    void readForRollback(){acquire(false);}

    private void acquire(boolean write){
        if(!TransactionSynchronizationManager.isActualTransactionActive() || !TransactionSynchronizationManager.isSynchronizationActive() || TransactionSynchronizationManager.isCurrentTransactionReadOnly())
            throw new IllegalStateException("Security gate requires a read-write transaction.");
        Object key=transaction();if(key==null)throw new IllegalStateException("Missing JPA transaction.");
        Boolean existing=HELD.get().get(key);
        if(existing!=null){if(write && !existing)throw new IllegalStateException("Security read-to-write lock upgrades are forbidden.");return;}
        var rows=em.createNativeQuery("select id from incident_security_lock where id=1"+(write?" for update":sharedClause())).getResultList();
        if(rows.size()!=1)throw new IllegalStateException("Incident security lock migration is missing.");
        HELD.get().put(key,write);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){
            @Override public void afterCompletion(int status){Map<Object,Boolean> map=HELD.get();map.remove(key);if(map.isEmpty())HELD.remove();}
        });
    }
}
