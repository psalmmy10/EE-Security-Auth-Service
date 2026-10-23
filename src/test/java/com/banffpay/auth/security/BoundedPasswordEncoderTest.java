package com.banffpay.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.pay.auth.exception.ServiceBusyException;
import com.pay.auth.security.BoundedPasswordEncoder;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BoundedPasswordEncoderTest {

    @Test
    void shedsLoadWhenHashingCapacityIsSaturated() throws Exception {
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        PasswordEncoder slow = new PasswordEncoder() {
            @Override
            public String encode(CharSequence raw) {
                inside.countDown();
                try {
                    release.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return "hash";
            }

            @Override
            public boolean matches(CharSequence raw, String encoded) {
                return true;
            }
        };
        BoundedPasswordEncoder bounded = new BoundedPasswordEncoder(slow, 1, Duration.ofMillis(50));

        Thread holder = Thread.ofVirtual().start(() -> bounded.encode("first"));
        assertThat(inside.await(2, TimeUnit.SECONDS)).isTrue();

        assertThatThrownBy(() -> bounded.encode("second")).isInstanceOf(ServiceBusyException.class);

        release.countDown();
        holder.join();
        assertThat(bounded.matches("x", "hash")).isTrue();
    }
}
