package info.debatty.java.spamsum;

/**
 * A Java implementation of SpamSum / SSDeep / Context Triggered Piecewise Hashing
 * 
 * http://www.samba.org/ftp/unpacked/junkcode/spamsum/
 * http://ssdeep.sourceforge.net/
 * 
 * 
 * @author Thibault Debatty
 */
public class SpamSum {
    
    public static void main (String[] args) {
        
        String s1 = "This is a string that might be a spam... Depends on the "
                + "hash, if it looks like a known hash...\n";
        String s2 = "Play to win  Download Casino King Spin now\n";
        
        SpamSum s = new SpamSum();
        
        // 3:hMCEqNE0M+YFFWV5wdgHMyA8FNzs1b:hujkYFFWV51HM8Lzs1b
        System.out.println(s.HashString(s1));
        // hMCEqNE0M+YFFWV5wdgHMyA8FNzs1b
        System.out.println(s.Left());
        
        // 3:Y0ujLEEz6KxMENJv:Y0u3tz68/v
        System.out.println(s.HashString(s2));
    }
    
    protected static final long HASH_PRIME = 0x01000193;
    protected static final long HASH_INIT = 0x28021967;
    protected static final char[] B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
    
    // The original algorithm works using UINT32 => 2 ^ 32
    protected static final long UINT32 = (long)2 << 31;

    protected int MIN_BLOCKSIZE = 3;
    protected int SPAMSUM_LENGTH = 64;
    protected int CHARACTERS = 64;
    
    protected int blocksize;
    protected char[] left;
    protected char[] right;
    

    /**
     * Computes and returns the spamsum signature of this string.
     * E.g. : 3:hMCEqNE0M+YFFWV5wdgHMyA8FNzs1b:hujkYFFWV51HM8Lzs1b
     * The block size is automatically computed
     * 
     * @param string
     * @return spamsum signature
     */
    public String HashString(String string) {
        return HashString(string, 0);
    }
    
    /**
     * Computes and returns the spamsum signature of this string.
     * E.g. : 3:hMCEqNE0M+YFFWV5wdgHMyA8FNzs1b:hujkYFFWV51HM8Lzs1b
     * 
     * @param string
     * @param bsize block size; if 0, the block size is automatically computed
     * @return spamsum signature
     */
    public String HashString(String string, int bsize) {
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

            left = new char[SPAMSUM_LENGTH];
            right = new char[SPAMSUM_LENGTH];

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
                    
                    left[j] = B64[(int) (h2 % CHARACTERS)];
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
                    right[k] = B64[(int) (h3 % CHARACTERS)];
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
                left[j] = B64[(int) (h2 % CHARACTERS)];
                right[k] = B64[(int) (h3 % CHARACTERS)];
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

        return toString();
    }

    @Override
    public String toString() {
        return "" + blocksize + ":"
                + Left() + ":"
                + Right();
    }

    /**
     * 
     * @return block size
     */
    public long BlockSize() {
        return blocksize;
    }

    /**
     * 
     * @return left part of the signature
     */
    public String Left() {
        return String.valueOf(left).trim();
    }

    /**
     * 
     * @return right part of the signature
     */
    public String Right() {
        return String.valueOf(right).trim();
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