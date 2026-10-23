package com.pay.auth.security;

import org.springframework.security.crypto.password.PasswordEncoder;

import com.pay.auth.exception.ServiceBusyException;

import java.time.Duration;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Decorator that caps concurrent password hashing.
 * <p>
 * Why: with virtual threads, 10,000 concurrent logins are cheap to <em>accept</em>, but BCrypt
 * is CPU-bound (~250 ms at strength 12). Unbounded, a credential-stuffing burst would pin every
 * carrier thread and starve all other requests. A fair semaphore sized to the core count keeps
 * CPU saturation bounded and sheds excess load with a 503 instead of collapsing.
 * Waiting virtual threads park without consuming a carrier.
 */
public final class BoundedPasswordEncoder implements PasswordEncoder {

    private final PasswordEncoder delegate;
    private final Semaphore permits;
    private final long acquireTimeoutMillis;

    public BoundedPasswordEncoder(PasswordEncoder delegate, int maxConcurrent, Duration acquireTimeout) {
        if (maxConcurrent < 1) {
            throw new IllegalArgumentException("maxConcurrent must be >= 1");
        }
        this.delegate = delegate;
        this.permits = new Semaphore(maxConcurrent, true);
        this.acquireTimeoutMillis = acquireTimeout.toMillis();
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return guarded(() -> delegate.encode(rawPassword));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return guarded(() -> delegate.matches(rawPassword, encodedPassword));
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        return delegate.upgradeEncoding(encodedPassword);
    }

    private <T> T guarded(Supplier<T> operation) {
        boolean acquired = false;
        try {
            acquired = permits.tryAcquire(acquireTimeoutMillis, TimeUnit.MILLISECONDS);
            if (!acquired) {
                throw new ServiceBusyException("password hashing capacity exhausted");
            }
            return operation.get();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new ServiceBusyException("interrupted while waiting for hashing capacity", ex);
        } finally {
            if (acquired) {
                permits.release();
            }
        }
    }
}
