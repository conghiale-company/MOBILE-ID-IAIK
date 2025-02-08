package vn.mobileid.testiaik.hsm;

import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.Token.SessionReadWriteBehavior;
import iaik.pkcs.pkcs11.Token.SessionType;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

public class HSMSessionManager {

    private final static int DEFAULT_MAX_SESSIONS = 32;

    // token instance
    private final Token token;

    // maximum number of sessions to open with this token
    private final int maxSessions;

    // total number of active sessions
    private AtomicInteger activeSessions = new AtomicInteger();

    // pool of available object sessions
    private final Pool objSessions;

    // pool of available operation sessions
    private final Pool opSessions;

    // maximum number of active sessions during this invocation, for debugging
    //private int maxActiveSessions;
    //private Object maxActiveSessionsLock;
    // flags to use in the C_OpenSession() call
    private final boolean rwSession;

    HSMSessionManager(Token token) throws TokenException {
        long n;
        if (token.getTokenInfo().isWriteProtected()) {
            rwSession = SessionReadWriteBehavior.RO_SESSION;
            n = token.getTokenInfo().getMaxSessionCount();
        } else {
            rwSession = SessionReadWriteBehavior.RW_SESSION;
            n = token.getTokenInfo().getMaxRwSessionCount();
        }
        if (n == PKCS11Constants.CK_EFFECTIVELY_INFINITE) {
            n = Integer.MAX_VALUE;
        } else if ((n == PKCS11Constants.CK_UNAVAILABLE_INFORMATION) || (n < 0)) {
            // choose an arbitrary concrete value
            n = DEFAULT_MAX_SESSIONS;
        }
        maxSessions = (int) Math.min(n, Integer.MAX_VALUE);
        this.token = token;
        this.objSessions = new Pool(this);
        this.opSessions = new Pool(this);

    }

    Session getObjSession() throws TokenException {
        Session session = objSessions.poll();
        if (session != null) {
            return ensureValid(session);
        }
        session = opSessions.poll();
        if (session != null) {
            return ensureValid(session);
        }
        session = openSession();
        return ensureValid(session);
    }

    Session getOpSession() throws TokenException {
        Session session = opSessions.poll();
        if (session != null) {
            return ensureValid(session);
        }
        // create a new session rather than re-using an obj session
        // that avoids potential expensive cancels() for Signatures & RSACipher
        if (maxSessions == Integer.MAX_VALUE
                || activeSessions.get() < maxSessions) {
            session = openSession();
            return ensureValid(session);
        }
        session = objSessions.poll();
        if (session != null) {
            return ensureValid(session);
        }
        throw new TokenException("Could not obtain session");
    }

    private Session ensureValid(Session session) throws TokenException {
        if (session.getToken().getSlot().getSlotInfo().isTokenPresent() == false) {
            throw new TokenException("Token has been removed");
        }

        return session;
    }

    Session killSession(Session session) throws TokenException {
        if ((session == null) || (session.getToken().getSlot().getSlotInfo().isTokenPresent() == false)) {
            return null;
        }

        closeSession(session);
        return null;
    }

    Session releaseSession(Session session) throws TokenException {
        if ((session == null) || (session.getToken().getSlot().getSlotInfo().isTokenPresent() == false)) {
            return null;
        }

        if (session.hasObjects()) {
            objSessions.release(session);
        } else {
            opSessions.release(session);
        }
        return null;
    }

    void demoteObjSession(Session session) throws TokenException {
        if (session.getToken().getSlot().getSlotInfo().isTokenPresent() == false) {
            return;
        }

        boolean present = objSessions.remove(session);
        if (present == false) {
            // session is currently in use
            // will be added to correct pool on release, nothing to do now
            return;
        }
        opSessions.release(session);
    }

    private Session openSession() throws TokenException {
        if ((maxSessions != Integer.MAX_VALUE)
                && (activeSessions.get() >= maxSessions)) {
            throw new TokenException("No more sessions available");
        }

        Session session = token.openSession(SessionType.SERIAL_SESSION, rwSession, null, null);
        activeSessions.incrementAndGet();

        return session;
    }

    private void closeSession(Session session) throws TokenException {
        session.closeSession();
        activeSessions.decrementAndGet();
    }

    public static final class Pool {

        private final HSMSessionManager mgr;

        private final ConcurrentLinkedDeque<Session> pool;

        Pool(HSMSessionManager mgr) {
            this.mgr = mgr;
            pool = new ConcurrentLinkedDeque<Session>();
        }

        boolean remove(Session session) {
            return pool.remove(session);
        }

        Session poll() {
            return pool.pollLast();
        }

        void release(Session session) throws TokenException {
            pool.offer(session);
            //session has object
            if (session.hasObjects()) {
                return;
            }

            int n = pool.size();
            if (n < 5) {
                return;
            }

            Session oldestSession;
            //long time = System.currentTimeMillis();
            int i = 0;
            // Check if the session head is too old and continue through queue
            // until only one is left.
            do {
                oldestSession = pool.peek();
                if (oldestSession == null || !pool.remove(oldestSession)) {
                    break;
                }

                i++;
                mgr.closeSession(oldestSession);

            } while ((n - i) > 1);

        }
    }
}
