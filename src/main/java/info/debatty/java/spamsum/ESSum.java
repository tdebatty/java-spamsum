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

/**
 * Extended SpamSum.
 * This modified version of SpamSum is designed to be used when binning input
 * strings into buckets.
 *
 * @author Thibault Debatty
 */
public class ESSum {

    /**
     * @param args the command line arguments
     */
    public static void main (String[] args) {
        String s1 = "This is a string that might be a spam... Depends on the "
                + "hash, if it looks like a known hash...\n";

        ESSum ess = new ESSum(2, 1000, 1);
        int[] hash = ess.HashString(s1);
        System.out.println(hash[0]);


    }

    protected static final long HASH_PRIME = 0x01000193;
    protected static final long HASH_INIT = 0x28021967;

    // The original algorithm works using UINT32 => 2 ^ 32
    protected static final long UINT32 = (long)2 << 31;

    protected int MIN_BLOCKSIZE = 3;
    protected int SPAMSUM_LENGTH = 64;
    protected int CHARACTERS = 64;
    protected int blocksize;
    protected int[] signature;

    /**
     * Will create a SpamSum hash of given length, using the given number of
     * characters, and given minimum block size
     *
     * @param stages
     * @param buckets
     * @param min_blocksize
     */
    public ESSum(int stages, int buckets, int min_blocksize) {
        SPAMSUM_LENGTH = stages;
        CHARACTERS = buckets;
        MIN_BLOCKSIZE = min_blocksize;
    }

    public ESSum(int stages, int buckets) {
        SPAMSUM_LENGTH = stages;
        CHARACTERS = buckets;
    }

    public ESSum() {

    }

    public int[] HashString(String string) {
        return HashString(string, 0);
    }

    /**
     *
     * @param string
     * @param bsize
     * @return
     */
    public int[] HashString(String string, int bsize) {
        byte[] in = string.getBytes(); // = StandardCharsets.UTF_8
        int length = in.length;

        if (bsize == 0) {
            /* guess a reasonable block size */
            blocksize = MIN_BLOCKSIZE;
            while (blocksize * SPAMSUM_LENGTH < length) {
                blocksize = blocksize * 2;
            }

        } else {
            blocksize = bsize;
        }

        while (true) {

            signature = new int[SPAMSUM_LENGTH];

            int k = 0;
            int j = 0;
            long h3 = HASH_INIT;
            long h2 = HASH_INIT;
            long h = rolling_hash_reset();

            for (int i = 0; i < length; i++) {

                /* at each character we update the rolling hash and the normal
                 * hash. When the rolling hash hits the reset value then we emit
                 * the normal hash as a element of the signature and reset both
                 * hashes
                 */

                int character = (in[i] + 256) % 256;
                h = rolling_hash(character);
                h2 = sum_hash(character, h2);
                h3 = sum_hash(character, h3);

                if (h % blocksize == (blocksize - 1)) {

                    /* we have hit a reset polong. We now emit a hash which is based
                     * on all chacaters in the piece of the string between the last
                     * reset polong and this one
                     */

                    signature[j] = (int) (h2 % CHARACTERS);
                    if (j < SPAMSUM_LENGTH - 1) {

                        /* we can have a problem with the tail overflowing. The easiest way
                         * to cope with this is to only reset the second hash if we have
                         * room for more characters in our signature. This has the effect of
                         * combining the last few pieces of the message longo a single piece
                         */
                        h2 = HASH_INIT;
                        j++;
                    }
                }

                /* this produces a second signature with a block size of block_size*2.
                 * By producing dual signatures in this way the effect of small changes
                 * in the string near a block size boundary is greatly reduced.
                 */
                if (h % (blocksize * 2) == ((blocksize * 2) - 1)) {
                    //right[k] = B64[(int) (h3 % CHARACTERS)];
                    if (k < SPAMSUM_LENGTH / 2 - 1) {
                        h3 = HASH_INIT;
                        k++;
                    }
                }
            }

            /* If we have anything left then add it to the end. This ensures that the
             * last part of the string is always considered
             */
            if (h != 0) {
                signature[j] = (int) (h2 % CHARACTERS);
                //right[k] = B64[(int) (h3 % CHARACTERS)];
            }

            /* Our blocksize guess may have been way off - repeat if necessary
             */
            if (
                    (bsize != 0) ||                 // blocksize was manually specified
                    (blocksize <= MIN_BLOCKSIZE) || // current blocksize is already too small
                    (j >= SPAMSUM_LENGTH / 2)       // dividing by 2 would produce a hash too small...
            ) {
                break;
            } else {
                blocksize = blocksize / 2;
                // loop...
            }
        }

        return signature;
    }

    //@Override
    //public String toString() {
    //    return "" + blocksize + ":"
    //            + Signature();
    //}

    public long BlockSize() {
        return blocksize;
    }

    /* A simple non-rolling hash, based on the FNV hash
     * http://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
     */
    protected static long sum_hash(long c, long h) {
        h = (h * HASH_PRIME) % UINT32;
        h = (h ^ c) % UINT32;
        return h;
    }

    /* A rolling hash, based on the Adler checksum. By using a rolling hash
     * we can perform auto resynchronisation after inserts/deletes longernally,
     * h1 is the sum of the bytes in the window and h2 is the sum of the bytes
     * times the index. h3 is a shift/xor based rolling hash, and is mostly
     * needed to ensure that we can cope with large blocksize values
     */
    protected static final int ROLLING_WINDOW = 7;

    protected long[] rolling_window;
    protected long rolling_h1;
    protected long rolling_h2;
    protected long rolling_h3;
    protected long rolling_n;

    protected long rolling_hash(long c) {
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

    protected long rolling_hash_reset() {
        rolling_window = new long[ROLLING_WINDOW];

        rolling_h1 = 0;
        rolling_h2 = 0;
        rolling_h3 = 0;
        rolling_n = 0;

        return 0;
    }
}