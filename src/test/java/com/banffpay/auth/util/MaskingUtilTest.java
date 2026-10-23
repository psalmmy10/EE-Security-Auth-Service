package com.banffpay.auth.util;

import org.junit.jupiter.api.Test;

import com.pay.auth.util.MaskingUtil;

import static org.assertj.core.api.Assertions.assertThat;

class MaskingUtilTest {

    @Test
    void masksLocalPartOfEmail() {
        assertThat(MaskingUtil.maskEmail("kayode@banffpay.com")).isEqualTo("ka****@banffpay.com");
    }

    @Test
    void handlesShortAndMalformedInput() {
        assertThat(MaskingUtil.maskEmail("k@x.io")).isEqualTo("k****@x.io");
        assertThat(MaskingUtil.maskEmail("no-at-sign")).isEqualTo("****");
        assertThat(MaskingUtil.maskEmail(null)).isNull();
    }
}
