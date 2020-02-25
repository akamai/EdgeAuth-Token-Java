package com.akamai.edgeauth.hexutils;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;

import static com.akamai.edgeauth.hexutils.DataTypeConverter.parseHexBinary;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class DataTypeConverterTest {
    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {"00", new byte[]{0x00}},
            {"0A", new byte[]{0x0A}},
            {"ABCD", new byte[]{(byte) 0xAB, (byte) 0xCD}},
            {"DEADBEEF", new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF}},
            {"CAFEBABE", new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE}}});
    }

    private String valueAsString;
    private byte[] valueAsByteArray;

    public DataTypeConverterTest(String valueAsString, byte[] valueAsByteArray) {
        this.valueAsString = valueAsString;
        this.valueAsByteArray = valueAsByteArray;
    }

    @Test
    public void convertsHexadecimalStringsToByteArrays() {
        assertArrayEquals(parseHexBinary(valueAsString), valueAsByteArray);
    }

    @Test
    public void throwsIllegalArgumentExceptionWhenInputHasOddNumberOfCharacters() {
        try {
            parseHexBinary("0");
            fail("should have thrown exception");
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "hexBinary needs to be even-length: 0");
            return;
        }
    }

    @Test
    public void throwsIllegalArgumentExceptionWhenInputContainsIllegalCharacter() {
        try {
            parseHexBinary("0G");
            fail("should have thrown exception");
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "contains illegal character for hexBinary: 0G");
        }
    }
}
