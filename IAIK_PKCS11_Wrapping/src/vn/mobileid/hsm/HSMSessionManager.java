/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package vn.mobileid.hsm;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.Token.SessionReadWriteBehavior;
import iaik.pkcs.pkcs11.Token.SessionType;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

/**
 *
 * @author Tan_Hung
 */
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

//    private final boolean rwSession;
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
            throw new TokenException("Invalid session or token has been removed");
        }

        closeSession(session);
        return null;
    }

    Session releaseSession(Session session) throws TokenException {
        if ((session == null) || (session.getToken().getSlot().getSlotInfo().isTokenPresent() == false)) {
            throw new TokenException("Invalid session or token has been removed");
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
            if (session == null || !session.getToken().getSlot().getSlotInfo().isTokenPresent()) {
                return; // session is invalid, do nothing
            }

            if (session.hasObjects()) {
                return; // session has objects, do not release it to the pool
            }

            pool.offer(session); // add session to the pool

            // If pool is full, remove some old sessions
            if (pool.size() > 5) {
                removeOldSessions();
            }
        }

        private void removeOldSessions() throws TokenException {
            while (pool.size() > 5) {
                Session oldestSession = pool.peek();
                if (oldestSession == null || !pool.remove(oldestSession)) {
                    break; // no more sessions to remove
                }
                mgr.closeSession(oldestSession);
            }
        }

    }
}
