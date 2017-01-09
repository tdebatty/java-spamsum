/*
 * The MIT License
 *
 * Copyright 2017 Thibault Debatty.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package info.debatty.java.spamsum;

import info.debatty.java.stringsimilarity.Levenshtein;

/**
 * A Java implementation of SpamSum / SSDeep / Context Triggered Piecewise
 * Hashing.
 *
 * Original C code by Andrew Tridgell.
 * http://www.samba.org/ftp/unpacked/junkcode/spamsum/
 * http://ssdeep.sourceforge.net/
 *
 *
 * @author Thibault Debatty
 */
public class SpamSum {

    /**
     * A simple example.
     * @param args
     */
    public static void main(final String[] args) {

        String s1 = "This is a string that might be a spam... Depends on the "
                + "hash, if it looks like a known hash...\n";
        String s2 = "Play to win  Download Casino King Spin now\n";

        SpamSum s = new SpamSum();

        // 3:hMCEqNE0M+YFFWV5wdgHMyA8FNzs1b:hujkYFFWV51HM8Lzs1b
        System.out.println(s.hashString(s1));

        // 3:Y0ujLEEz6KxMENJv:Y0u3tz68/v
        System.out.println(s.hashString(s2));
    }

    private static final long HASH_PRIME = 0x01000193;
    private static final long HASH_INIT = 0x28021967;
    private static final char[] B64 =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    .toCharArray();

    // The original algorithm works using UINT32 => 2 ^ 32
    private static final long UINT32 = (long) 2 << 31;

    private static final int MIN_BLOCKSIZE = 3;
    private static final int SPAMSUM_LENGTH = 64;
    private static final int CHARACTERS = 64;

    /**
     * Computes and returns the spamsum signature of this string.
     * E.g. : 3:hMCEqNE0M+YFFWV5wdgHMyA8FNzs1b:hujkYFFWV51HM8Lzs1b
     * The block size is automatically computed
     *
     * @param string
     * @return spamsum signature
     */
    public final Signature hashString(final String string) {
        return hashString(string, 0);
    }

    /**
     * Computes and returns the spamsum signature of this string.
     * E.g. : 3:hMCEqNE0M+YFFWV5wdgHMyA8FNzs1b:hujkYFFWV51HM8Lzs1b
     *
     * @param string
     * @param bsize block size; if 0, the block size is automatically computed
     * @return spamsum signature
     */
    public final Signature hashString(final String string, final int bsize) {
        byte[] in = string.getBytes(); // = StandardCharsets.UTF_8
        int length = in.length;

        int blocksize = bsize;
        if (bsize == 0) {
            /* guess a reasonable block size */
            blocksize = MIN_BLOCKSIZE;
            while (blocksize * SPAMSUM_LENGTH < length) {
                blocksize = blocksize * 2;
            }
        }

        char[] left;
        char[] right;

        while (true) {

            left = new char[SPAMSUM_LENGTH];
            right = new char[SPAMSUM_LENGTH];

            int k = 0;
            int j = 0;
            long h3 = HASH_INIT;
            long h2 = HASH_INIT;
            long h = rollingHashReset();

            for (int i = 0; i < length; i++) {

                // at each character we update the rolling hash and the normal
                // hash. When the rolling hash hits the reset value then we emit
                // the normal hash as a element of the signature and reset both
                // hashes
                int character = (in[i] + 256) % 256;
                h = rollingHash(character);
                h2 = sumHash(character, h2);
                h3 = sumHash(character, h3);

                if (h % blocksize == (blocksize - 1)) {

                    // we have hit a reset polong. We now emit a hash which is
                    // based on all chacaters in the piece of the string between
                    // the last reset polong and this one
                    left[j] = B64[(int) (h2 % CHARACTERS)];
                    if (j < SPAMSUM_LENGTH - 1) {

                        // we can have a problem with the tail overflowing. The
                        // easiest way to cope with this is to only reset the
                        // second hash if we have room for more characters in
                        // our signature. This has the effect of combining the
                        // last few pieces of the message longo a single piece
                        h2 = HASH_INIT;
                        j++;
                    }
                }

                // this produces a second signature with a block size of
                // block_size*2. By producing dual signatures in this way the
                // effect of small changes in the string near a block size
                // boundary is greatly reduced.
                if (h % (blocksize * 2) == ((blocksize * 2) - 1)) {
                    right[k] = B64[(int) (h3 % CHARACTERS)];
                    if (k < SPAMSUM_LENGTH / 2 - 1) {
                        h3 = HASH_INIT;
                        k++;
                    }
                }
            }

            // If we have anything left then add it to the end. This ensures
            // that the last part of the string is always considered
            if (h != 0) {
                left[j] = B64[(int) (h2 % CHARACTERS)];
                right[k] = B64[(int) (h3 % CHARACTERS)];
            }

            // blocksize guess may have been way off - repeat, except if:
            // - blocksize was manually specified
            // - current blocksize is already too small
            // - dividing by 2 would produce a hash too small...

            if (
                    bsize != 0
                    || blocksize <= MIN_BLOCKSIZE
                    || j >= SPAMSUM_LENGTH / 2) {
                break;
            } else {
                blocksize = blocksize / 2;
                // loop...
            }
        }

        return new Signature(
                String.valueOf(left).trim(),
                String.valueOf(right).trim(),
                blocksize);
    }

    /**
     * A simple non-rolling hash, based on the FNV hash.
     * http://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
     */
    private static long sumHash(final long c, final long h) {
        long result = (h * HASH_PRIME) % UINT32;
        result = (result ^ c) % UINT32;
        return result;
    }

    /* A rolling hash, based on the Adler checksum. By using a rolling hash
     * we can perform auto resynchronisation after inserts/deletes longernally,
     * h1 is the sum of the bytes in the window and h2 is the sum of the bytes
     * times the index. h3 is a shift/xor based rolling hash, and is mostly
     * needed to ensure that we can cope with large blocksize values
     */
    private static final int ROLLING_WINDOW = 7;

    private long[] rolling_window;
    private long rolling_h1;
    private long rolling_h2;
    private long rolling_h3;
    private long rolling_n;

    private long rollingHash(final long c) {
        rolling_h2 -= rolling_h1;
        rolling_h2 = (rolling_h2 + ROLLING_WINDOW * c) % UINT32;

        rolling_h1 = (rolling_h1 + c) % UINT32;
        rolling_h1 -= rolling_window[(int) rolling_n % ROLLING_WINDOW];

        rolling_window[(int) (rolling_n % ROLLING_WINDOW)] = c;
        rolling_n++;

        rolling_h3 = ((rolling_h3 << 5) & 0xFFFFFFFF) % UINT32;
        rolling_h3 = (rolling_h3 ^ c) % UINT32; // Bitwize XOR

        return (rolling_h1 + rolling_h2 + rolling_h3) % UINT32;
    }

    private long rollingHashReset() {
        rolling_window = new long[ROLLING_WINDOW];

        rolling_h1 = 0;
        rolling_h2 = 0;
        rolling_h3 = 0;
        rolling_n = 0;

        return 0;
    }



    /**
     * Compute the similarity between two SpamSum signatures.
     *
     * C code originally translated by Mahmood S. Zargar
     * https://github.com/retrography/JessDeep/
     *
     * @param sig1
     * @param sig2
     * @return
     */
    public final int match(final String sig1, final String sig2) {

        // each signature looks like  "size:abc:def"
        String[] split1 = sig1.split(":", 2);
        String[] split2 = sig2.split(":", 2);

        if (split1.length != 2 || split2.length != 2) {
            return 0;
        }

        int block_size1 = Integer.parseInt(split1[0]);
        int block_size2 = Integer.parseInt(split2[0]);

        //if the blocksizes don't match then we are comparing
        // apples to oranges ...
        if (block_size1 != block_size2
                && block_size1 != block_size2 * 2
                && block_size2 != block_size1 * 2) {
            return 0;
        }

        // there is very little information content is sequences of
        // the same character like 'LLLLL'. Eliminate any sequences
        // longer than 3.
        String s1 = eliminateSequences(split1[1]);
        String s2 = eliminateSequences(split2[1]);

        // now break them into the two pieces
        // first block is abc:def
        String s1_1 = s1;
        String s2_1 = s2;

        // second block is :def
        String s1_2 = ":" + s1.split(":")[1];
        String s2_2 = ":" + s2.split(":")[1];

        // compute score
        if (block_size1 == block_size2) {
            return Math.max(
                    score(s1_1, s2_1, block_size1),
                    score(s1_2, s2_2, block_size1));

        } else if (block_size1 == block_size2 * 2) {
            return score(s1_1, s2_2, block_size1);

        }

        return score(s1_2, s2_1, block_size2);
    }

    /**
     * Compute the match score between two signatures.
     * @param sig1
     * @param sig2
     * @return
     */
    public final int match(final Signature sig1, final Signature sig2) {

        // This is dirty!
        return match(sig1.toString(), sig2.toString());
    }

    /**
     *
     * Compute the score between blocks using Levenshtein edit distance and
     * rescaling to return a score between 0 and 100.
     *
     * C code originally translated by Mahmood S Zargar.
     * https://github.com/retrography/JessDeep/
     *
     * @param s1
     * @param s2
     * @param block_size
     * @return
     */
    private int score(final String s1, final String s2, final int block_size) {

        int len1 = s1.length();
        int len2 = s2.length();

        if (len1 > SPAMSUM_LENGTH || len2 > SPAMSUM_LENGTH) {
            /* not a real spamsum signature? */
            return 0;
        }

        // compute the edit distance between the two strings
        Levenshtein levenshtein = new Levenshtein();
        int score = (int) levenshtein.distance(s1, s2);

        // Rescale to get a score between 0 and 100
        // and independant of the length of strings
        // the original C code first multiplies by 64 (SPAMSUM_LENGTH) and
        // then divides by 64, which introduces some rounding approximations
        // hence we cannot simplify the line below... :(
        score = (score * SPAMSUM_LENGTH) / (len1 + len2) * 100 / SPAMSUM_LENGTH;

        // it is possible to get a score above 100 here, but it is a
        // really terrible match
        if (score >= 100) {
            return 0;
        }

        // now re-scale on a 0-100 scale with 0 being a poor match and
        // 100 being a excellent match.
        score = 100 - score;

        // when the blocksize is small, don't exaggerate the match size
        if (score > block_size / MIN_BLOCKSIZE * Math.min(len1, len2)) {
            score = block_size / MIN_BLOCKSIZE * Math.min(len1, len2);
        }

        return score;
    }

    /**
     * Eliminate sequences containing the same repeated character.
     *
     * C code originally translated by Mahmood S. Zargar
     * https://github.com/retrography/JessDeep/
     *
     * @param str
     * @return
     */
    private String eliminateSequences(final String str) {

        char[] str_array = str.toCharArray();
        char[] ret =  str.toCharArray();
        int len = ret.length;

        int i, j;
        for (i = 3, j = 3; i < len; i++) {
            if (str_array[i] != str_array[i - 1]
                    || str_array[i] != str_array[i - 2]
                    || str_array[i] != str_array[i - 3]) {
                ret[j++] = str_array[i];
            }
        }

        return new String(ret);
    }
}