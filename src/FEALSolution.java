/*
 * The FEAL cipher
 */

import java.io.BufferedReader;
import java.io.FileReader;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * FEAL4 Cipher - Linear Cryptanalysis
 */
public class FEALSolution extends FEAL {

    public static void main(String args[]) throws Exception {
        FEALSolution solution = new FEALSolution();
        List<PlainAndCipherText> pairs = solution.getPairs(args[0]);
        solution.triggerFEAL4Attack(pairs);
    }


    /**
     * Method to retrieve the bits from a 32 bit word
     *
     * @param number
     * @param bits
     * @return
     */
    public int[] getBits(int number, int... bits) {
        int[] retVal = new int[bits.length];
        for (int i = 0; i < bits.length; i++) {
            int shift = 32 - bits[i] - 1;
            int result = (number >> shift) & 1;
            retVal[i] = result;
        }
        return retVal;
    }

    /**
     * Method to evaluate the constant required for k0 prime evaluation
     *
     * @param pair
     * @param k0_prime
     * @return
     */
    public int evaluateConstant_k0_prime(PlainAndCipherText pair, SubKey k0_prime) {
        int l0_xor_r0_xor_l4 = get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ get(BytesPair.L4, pair);
        int[] S_5_13_21 = getBits(l0_xor_r0_xor_l4, 5, 13, 21);
        int l0_xor_l4_xor_r4 = get(BytesPair.L0, pair) ^ get(BytesPair.L4, pair) ^ get(BytesPair.R4, pair);
        int[] s_15 = getBits(l0_xor_l4_xor_r4, 15);
        int l0_xor_r0_xor_k0_prime = get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ k0_prime.getKey();
        int[] s_15_f = getBits(f(l0_xor_r0_xor_k0_prime), 15);
        int retVal = (S_5_13_21[0] ^ S_5_13_21[1] ^ S_5_13_21[2]) ^ s_15[0] ^ s_15_f[0];
        return retVal;
    }

    /**
     * Method to determine the constant for k0
     *
     * @param pair
     * @param k0
     * @return
     */
    public int evaluateConstant_k0(PlainAndCipherText pair, SubKey k0) {
        int l0_xor_r0_xor_l4 = get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ get(BytesPair.L4, pair);
        int[] S_13 = getBits(l0_xor_r0_xor_l4, 13);
        int l0_xor_l4_xor_r4 = get(BytesPair.L0, pair) ^ get(BytesPair.L4, pair) ^ get(BytesPair.R4, pair);
        int[] s_7_15_23_31 = getBits(l0_xor_l4_xor_r4, 7, 15, 23, 31);
        int l0_xor_r0_xor_k0 = get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ k0.getKey();
        int[] s_7_15_23_31_f = getBits(f(l0_xor_r0_xor_k0), 7, 15, 23, 31);
        int retVal = (S_13[0] ^ (s_7_15_23_31[0] ^ s_7_15_23_31[1] ^ s_7_15_23_31[2] ^ s_7_15_23_31[3]) ^
                (s_7_15_23_31_f[0] ^ s_7_15_23_31_f[1] ^ s_7_15_23_31_f[2] ^ s_7_15_23_31_f[3]));
        return retVal;
    }

    public int evaluateConstant_k1_prime(PlainAndCipherText pair, SubKey k0, SubKey key) {
        int l0_xor_l4_xor_r4 = get(BytesPair.L0, pair) ^ get(BytesPair.L4, pair) ^ get(BytesPair.R4, pair);
        int[] S_5_13_21 = getBits(l0_xor_l4_xor_r4, 5, 13, 21);
        int f_l0_xor_r0_xor_k0 = f(get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ k0.getKey());
        int[] s_15 = getBits(f(get(BytesPair.L0, pair) ^ f_l0_xor_r0_xor_k0 ^ key.getKey()), 15);
        int retVal = (S_5_13_21[0] ^ S_5_13_21[1] ^ S_5_13_21[2]) ^ s_15[0];
        return retVal;
    }

    public int evaluateConstant_k1(PlainAndCipherText pair, SubKey k0, SubKey key) {
        int l0_xor_l4_xor_r4 = get(BytesPair.L0, pair) ^ get(BytesPair.L4, pair) ^ get(BytesPair.R4, pair);
        int[] s_13 = getBits(l0_xor_l4_xor_r4, 13);
        int f_l0_xor_r0_xor_k0 = f(get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ k0.getKey());
        int[] s_7_15_23_31 = getBits(f(get(BytesPair.L0, pair) ^ f_l0_xor_r0_xor_k0 ^
                key.getKey()), 7, 15, 23, 31);
        int retVal = (s_13[0] ^ s_7_15_23_31[0] ^ s_7_15_23_31[1]) ^ s_7_15_23_31[2] ^ s_7_15_23_31[3];
        return retVal;
    }

    public int evaluateConstant_k2_prime(PlainAndCipherText pair, SubKey k0, SubKey k1, SubKey key) {
        int l0_xor_r0_xor_l4 = get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ get(BytesPair.L4, pair);
        int[] s_5_13_21 = getBits(l0_xor_r0_xor_l4, 5, 13, 21);

        int f_l0_xor_r0_xor_k0 = f(get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ k0.getKey());
        int f_l0_xor_above_xor_k1 = f(get(BytesPair.L0, pair) ^ f_l0_xor_r0_xor_k0 ^ k1.getKey());
        int f_l0_xor_r0_xor_above_xor_k2 = f(get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^
                f_l0_xor_above_xor_k1 ^ key.getKey());
        int[] s_15 = getBits(f_l0_xor_r0_xor_above_xor_k2, 15);

        int retVal = (s_5_13_21[0] ^ s_5_13_21[1] ^ s_5_13_21[2]) ^ s_15[0];
        return retVal;
    }

    public int evaluateConstant_k2(PlainAndCipherText pair, SubKey k0, SubKey k1, SubKey key) {
        int l0_xor_r0_xor_l4 = get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ get(BytesPair.L4, pair);
        int[] s_13 = getBits(l0_xor_r0_xor_l4, 13);

        int f_l0_xor_r0_xor_k0 = f(get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ k0.getKey());
        int f_l0_xor_above_xor_k1 = f(get(BytesPair.L0, pair) ^ f_l0_xor_r0_xor_k0 ^ k1.getKey());
        int f_l0_xor_r0_xor_above_xor_k2 = f(get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^
                f_l0_xor_above_xor_k1 ^ key.getKey());
        int[] s_7_15_23_31 = getBits(f_l0_xor_r0_xor_above_xor_k2, 7, 15, 23, 31);

        int retVal = (s_13[0] ^ s_7_15_23_31[0] ^ s_7_15_23_31[1]) ^ s_7_15_23_31[2] ^ s_7_15_23_31[3];
        return retVal;
    }

    public int evaluateConstant_k3_prime(PlainAndCipherText pair, SubKey k0, SubKey k1, SubKey k2, SubKey key) {
        int l0_xor_l4_xor_r4 = get(BytesPair.L0, pair) ^ get(BytesPair.L4, pair) ^ get(BytesPair.R4, pair);
        int[] s_5_13_21 = getBits(l0_xor_l4_xor_r4, 5, 13, 21);

        int l0_xor_r0_xor_l4 = get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ get(BytesPair.L4, pair);
        int[] s_15_a = getBits(l0_xor_r0_xor_l4, 15);

        int f_l0_xor_r0_xor_k0 = f(get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ k0.getKey());
        int f_l0_xor_above_xor_k1 = f(get(BytesPair.L0, pair) ^ f_l0_xor_r0_xor_k0 ^ k1.getKey());
        int f_l0_xor_r0_xor_above_xor_k2 = f(get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^
                f_l0_xor_above_xor_k1 ^ k2.getKey());
        int f_l0_xor_above2_xor_k3 = f(get(BytesPair.L0, pair) ^ f_l0_xor_r0_xor_k0 ^
                f_l0_xor_r0_xor_above_xor_k2 ^ key.getKey());
        int[] s_15_b = getBits(f_l0_xor_above2_xor_k3, 15);

        int retVal = (s_5_13_21[0] ^ s_5_13_21[1] ^ s_5_13_21[2]) ^ s_15_a[0] ^ s_15_b[0];
        return retVal;
    }

    public int evaluateConstant_k3(PlainAndCipherText pair, SubKey k0, SubKey k1, SubKey k2, SubKey key) {
        int l0_xor_l4_xor_r4 = get(BytesPair.L0, pair) ^ get(BytesPair.L4, pair) ^ get(BytesPair.R4, pair);
        int[] s_13 = getBits(l0_xor_l4_xor_r4, 13);

        int l0_xor_r0_xor_l4 = get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ get(BytesPair.L4, pair);
        int[] s_7_15_23_31_a = getBits(l0_xor_r0_xor_l4, 7, 15, 23, 31);

        int f_l0_xor_r0_xor_k0 = f(get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^ k0.getKey());
        int f_l0_xor_above_xor_k1 = f(get(BytesPair.L0, pair) ^ f_l0_xor_r0_xor_k0 ^ k1.getKey());
        int f_l0_xor_r0_xor_above_xor_k2 = f(get(BytesPair.L0, pair) ^ get(BytesPair.R0, pair) ^
                f_l0_xor_above_xor_k1 ^ k2.getKey());
        int f_l0_xor_above2_xor_k3 = f(get(BytesPair.L0, pair) ^ f_l0_xor_r0_xor_k0 ^
                f_l0_xor_r0_xor_above_xor_k2 ^ key.getKey());
        int[] s_7_15_23_31_b = getBits(f_l0_xor_above2_xor_k3, 7, 15, 23, 31);

        int retVal = s_13[0] ^ (s_7_15_23_31_a[0] ^ s_7_15_23_31_a[1] ^ s_7_15_23_31_a[2] ^ s_7_15_23_31_a[3]) ^
                (s_7_15_23_31_b[0] ^ s_7_15_23_31_b[1] ^ s_7_15_23_31_b[2] ^ s_7_15_23_31_b[3]);
        return retVal;
    }

    /**
     * Method to get all the possible keys for the inner two bytes
     * i.e. 12 bits
     * @return
     */
    private List<SubKey> get_inner_bytes_candidates() {
        List<SubKey> retVal = new ArrayList<>();
        for (int i = 0; i < Math.pow(2, 12); i++) {
            int byte1 = (((i >> 6) & 0x3f) << 16);
            int byte2 = ((i & 0x3f) << 8);
            int bit12_key = byte1 + byte2;
            retVal.add(new SubKey(bit12_key));
        }
        //log("length of list returned = " + retVal.size());
        return retVal;
    }

    /**
     * method to get all the possible keys for a given innerKey
     * i.e. 20 bits
     * @param outerKey
     * @param innerKey
     * @return
     */
    private SubKey get_outer_bytes_candidate(int outerKey, int innerKey) {
        int a0 = (((outerKey & 0xf) >> 2) << 6) + ((innerKey >> 16) & 0xff);
        int a1 = ((outerKey & 0x3) << 6) + ((innerKey >> 8) & 0xff);

        int byte0 = (outerKey >> 12) & 0xff;
        int byte3 = (outerKey >> 4) & 0xff;

        int byte1 = byte0 ^ a0;
        int byte2 = byte3 ^ a1;

        int key = (byte0 << 24) + (byte1 << 16) + (byte2 << 8) + byte3;
        return new SubKey(key);
    }

    /**
     * Method to retrieve the plain and cipher text pairs from the mentioned file
     *
     * @param fileName
     * @return
     * @throws Exception
     */
    public List<PlainAndCipherText> getPairs(String fileName) throws Exception {

        List<PlainAndCipherText> retVal = new ArrayList<>();
        BufferedReader br = new BufferedReader(new FileReader(fileName));
        String plainText = null, cipherText = null, line = null;
        while ((line = br.readLine()) != null || (plainText != null || cipherText != null)) {
            if (line != null && line.startsWith("Plaintext"))
                plainText = line;
            else if (line != null && line.startsWith("Ciphertext"))
                cipherText = line;
            else {
                retVal.add(new PlainAndCipherText(plainText, cipherText));
                plainText = null;
                cipherText = null;
            }
        }
        return retVal;
    }

    void triggerFEAL4Attack(List<PlainAndCipherText> pairs) {

        Instant start = Instant.now();
        // trigger the evaluations of K0
        triggerK0Evaluation(pairs);
        Instant end = Instant.now();
        log("Execution of triggerFEAL4Attack() took: " + Duration.between(start, end));
    }

    private void triggerK0Evaluation(List<PlainAndCipherText> pairs) {

        List<SubKey> candidateK0s = get_inner_bytes_candidates();

        int k0_count = 0;
        for (SubKey candidatek0 : candidateK0s) {

            int iteration = 0, lastValue = 0;

            for (PlainAndCipherText pair : pairs) {
                int constant = evaluateConstant_k0_prime(pair, candidatek0);
                if (iteration != 0 && lastValue != constant) break;

                lastValue = constant;
                iteration++;
            }

            if (iteration == pairs.size()) {
                for (int i = 0; i < Math.pow(2, 20); i++) {

                    iteration = 0;
                    lastValue = 0;

                    SubKey possibleSubKey = get_outer_bytes_candidate(i, candidatek0.getKey());
                    for (PlainAndCipherText pair : pairs) {
                        int constant = evaluateConstant_k0(pair, possibleSubKey);

                        if (iteration != 0 && lastValue != constant) break;

                        lastValue = constant;
                        iteration++;
                    }

                    if (iteration == pairs.size()) {
                        triggerK1Evaluation(possibleSubKey, pairs);
                        k0_count++;
                    }
                }
            }
        }
//        log("Number of k0 keys = " + k0_count);

    }

    private void triggerK1Evaluation(SubKey k0, List<PlainAndCipherText> pairs) {
        List<SubKey> candidateK1s = get_inner_bytes_candidates();

        int k1_count = 0;
        for (SubKey candidatek1 : candidateK1s) {

            int iteration = 0, lastValue = 0;

            for (PlainAndCipherText pair : pairs) {
                int constant = evaluateConstant_k1_prime(pair, k0, candidatek1);
                if (iteration != 0 && lastValue != constant) break;

                lastValue = constant;
                iteration++;
            }

            if (iteration == pairs.size()) {
                for (int i = 0; i < Math.pow(2, 20); i++) {

                    iteration = 0;
                    lastValue = 0;

                    SubKey possibleSubKey = get_outer_bytes_candidate(i, candidatek1.getKey());
                    for (PlainAndCipherText pair : pairs) {
                        int constant = evaluateConstant_k1(pair, k0, possibleSubKey);

                        if (iteration != 0 && lastValue != constant) break;

                        lastValue = constant;
                        iteration++;
                    }

                    if (iteration == pairs.size()) {
                        k1_count++;
                        triggerK2Evaluation(k0, possibleSubKey, pairs);
                    }
                }
            }
        }
//        if (k1_count != 0) log("k1 count = " + k1_count);
    }

    private void triggerK2Evaluation(SubKey k0, SubKey k1, List<PlainAndCipherText> pairs) {
        List<SubKey> candidateK2s = get_inner_bytes_candidates();
        int k2_count = 0;
        for (SubKey candidatek2 : candidateK2s) {

            int iteration = 0, lastValue = 0;

            for (PlainAndCipherText pair : pairs) {
                int constant = evaluateConstant_k2_prime(pair, k0, k1, candidatek2);
                if (iteration != 0 && lastValue != constant) break;

                lastValue = constant;
                iteration++;
            }

            if (iteration == pairs.size()) {
                for (int i = 0; i < Math.pow(2, 20); i++) {

                    iteration = 0;
                    lastValue = 0;

                    SubKey possibleSubKey = get_outer_bytes_candidate(i, candidatek2.getKey());
                    for (PlainAndCipherText pair : pairs) {
                        int constant = evaluateConstant_k2(pair, k0, k1, possibleSubKey);

                        if (iteration != 0 && lastValue != constant) break;

                        lastValue = constant;
                        iteration++;
                    }

                    if (iteration == pairs.size()) {
                        k2_count++;
                        triggerK3Evaluation(k0, k1, possibleSubKey, pairs);
                    }
                }
            }
        }
//        if (k2_count != 0) log("k2 count = " + k2_count);
    }

    private void triggerK3Evaluation(SubKey k0, SubKey k1, SubKey k2, List<PlainAndCipherText> pairs) {
        List<SubKey> candidateK3s = get_inner_bytes_candidates();

        int k3_count = 0;
        for (SubKey candidatek3 : candidateK3s) {

            int iteration = 0, lastValue = 0;

            for (PlainAndCipherText pair : pairs) {
                int constant = evaluateConstant_k3_prime(pair, k0, k1, k2, candidatek3);
                if (iteration != 0 && lastValue != constant) break;

                lastValue = constant;
                iteration++;
            }

            if (iteration == pairs.size()) {
                for (int i = 0; i < Math.pow(2, 20); i++) {

                    iteration = 0;
                    lastValue = 0;

                    SubKey possibleSubKey = get_outer_bytes_candidate(i, candidatek3.getKey());
                    for (PlainAndCipherText pair : pairs) {
                        int constant = evaluateConstant_k3(pair, k0, k1, k2, possibleSubKey);

                        if (iteration != 0 && lastValue != constant) break;

                        lastValue = constant;
                        iteration++;
                    }

                    if (iteration == pairs.size()) {
                        k3_count++;
                        evaluateKeys(k0, k1, k2, possibleSubKey, pairs);
                    }
                }
            }
        }

//        if (k3_count != 0) log("k3 count = " + k3_count);

    }

    private void logPairs(List<PlainAndCipherText> pairs) {
        log("******************* pairs");
        for (PlainAndCipherText pair : pairs)
            log("Pair = " + pair);
    }

    public enum BytesPair {
        L0,
        R0,
        L4,
        R4;
    }

    private int get(BytesPair bytesPair, PlainAndCipherText pair) {
        switch (bytesPair) {
            case L0:
                return pack(pair.getPlain(), 0);
            case R0:
                return pack(pair.getPlain(), 4);
            case L4:
                return pack(pair.getCipher(), 0);
            case R4:
                return pack(pair.getCipher(), 4);
        }
        return 0;
    }

    private void evaluateKeys(SubKey k0, SubKey k1, SubKey k2, SubKey k3, List<PlainAndCipherText> pairs) {

        PlainAndCipherText lastPair = pairs.get(pairs.size() - 1);
        int y0 = f(get(BytesPair.L0, lastPair) ^ get(BytesPair.R0, lastPair) ^ k0.getKey());
        int y1 = f(get(BytesPair.L0, lastPair) ^ y0 ^ k1.getKey());
        int y2 = f(get(BytesPair.L0, lastPair) ^ get(BytesPair.R0, lastPair) ^ y1 ^ k2.getKey());
        int y3 = f(get(BytesPair.L0, lastPair) ^ y0 ^ y2 ^ k3.getKey());

        SubKey key4 = new SubKey(get(BytesPair.L0, lastPair) ^
                get(BytesPair.R0, lastPair) ^ y1 ^ y3 ^ get(BytesPair.L4, lastPair));
        SubKey key5 = new SubKey(get(BytesPair.R0, lastPair) ^ y1 ^ y3 ^ y0 ^ y2 ^
                get(BytesPair.R4, lastPair));

        int key[] = {k0.getKey(), k1.getKey(), k2.getKey(), k3.getKey(), key4.getKey(), key5.getKey()};

        for (PlainAndCipherText pair : pairs) {

            byte data[] = pair.getCipher();
            decrypt(data, key);
            StringBuilder sb = new StringBuilder(data.length * 2);
            for (byte b : data)
                sb.append(String.format("%02x", b));

            if (!pair.getPlainText().equals(sb.toString()))
                return;
        }

        logKeys(k0, k1, k2, k3, key4, key5, true);

    }

    private void logKeys(SubKey k0, SubKey k1, SubKey k2, SubKey k3, SubKey k4, SubKey k5, boolean binary) {
        if (binary) {
            StringBuilder sb = new StringBuilder();
            sb.append("k0 " + String.format("%32s", Integer.toBinaryString(k0.getKey())).replace(' ', '0'));
            sb.append("\tk1 " + String.format("%32s", Integer.toBinaryString(k1.getKey())).replace(' ', '0'));
            sb.append("\tk2 " + String.format("%32s", Integer.toBinaryString(k2.getKey())).replace(' ', '0'));
            sb.append("\tk3 " + String.format("%32s", Integer.toBinaryString(k3.getKey())).replace(' ', '0'));
            sb.append("\tk4 " + String.format("%32s", Integer.toBinaryString(k4.getKey())).replace(' ', '0'));
            sb.append("\tk5 " + String.format("%32s", Integer.toBinaryString(k5.getKey())).replace(' ', '0'));
            log(sb.toString());
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("k0 0x" + Integer.toHexString(k0.getKey()));
            sb.append("\tk1 0x" + Integer.toHexString(k1.getKey()));
            sb.append("\tk2 0x" + Integer.toHexString(k2.getKey()));
            sb.append("\tk3 0x" + Integer.toHexString(k3.getKey()));
            sb.append("\tk4 0x" + Integer.toHexString(k4.getKey()));
            sb.append("\tk5 0x" + Integer.toHexString(k5.getKey()));
            log(sb.toString());
        }
    }


    private static final class SubKey {
        private int key;
        private byte[] bytes = new byte[4];

        public SubKey(int key) {
            this.key = key;
            unpack(key, this.bytes, 0);
        }

        public byte[] getBytes() {
            return bytes;
        }

        public int getKey() {
            return key;
        }
    }

    private static final class PlainAndCipherText {
        private String plainText;
        private String cipherText;

        private int L0;
        private int R0;
        private int L4;
        private int R4;

        private static final int LEFT_RIGHT = 8;

        public PlainAndCipherText(String plainText1, String cipherText1) {
            this.plainText = plainText1.substring(plainText1.indexOf(' '), plainText1.length()).trim();
            this.L0 = pack(getBytes(this.plainText), 0);
            this.R0 = pack(getBytes(this.plainText), 4);
            this.cipherText = cipherText1.substring(cipherText1.indexOf(' '), cipherText1.length()).trim();
            this.L4 = pack(getBytes(this.cipherText), 0);
            this.R4 = pack(getBytes(this.cipherText), 4);
        }

        public byte[] getPlain() {
            return getBytes(plainText);
        }

        public byte[] getCipher() {
            return getBytes(cipherText);
        }

        public String getPlainText() {
            return plainText;
        }

        public String getCipherText() {
            return cipherText;
        }

        private byte[] getBytes(String text) {
            byte[] retVal = new byte[8];
            retVal[0] = (byte) (Integer.parseInt(text.substring(0, 2), 16) & 255);
            retVal[1] = (byte) (Integer.parseInt(text.substring(2, 4), 16) & 255);
            retVal[2] = (byte) (Integer.parseInt(text.substring(4, 6), 16) & 255);
            retVal[3] = (byte) (Integer.parseInt(text.substring(6, 8), 16) & 255);
            retVal[4] = (byte) (Integer.parseInt(text.substring(8, 10), 16) & 255);
            retVal[5] = (byte) (Integer.parseInt(text.substring(10, 12), 16) & 255);
            retVal[6] = (byte) (Integer.parseInt(text.substring(12, 14), 16) & 255);
            retVal[7] = (byte) (Integer.parseInt(text.substring(14, 16), 16) & 255);
            return retVal;
        }

        @Override
        public String toString() {
            return "PlainAndCipherText{" +
                    "plainText='" + plainText + '\'' +
                    ", cipherText='" + cipherText + '\'' +
                    ", L0=" + L0 +
                    ", R0=" + R0 +
                    ", L4=" + L4 +
                    ", R4=" + R4 +
                    '}';
        }
    }
}
