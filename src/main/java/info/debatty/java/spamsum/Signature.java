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
 * Represents a spamsum signature.
 * @author Thibault Debatty
 */
public class Signature {

    private final int blocksize;
    private final String left;
    private final String right;

    Signature(final String left, final String right, final int blocksize) {
        this.left = left;
        this.right = right;
        this.blocksize = blocksize;
    }

    @Override
    public final String toString() {
        return "" + blocksize + ":" + left + ":" +  right;
    }

    /**
     *
     * @return block size
     */
    public final long getBlockSize() {
        return blocksize;
    }

    /**
     *
     * @return left part of the signature
     */
    public final String getLeft() {
        return left;
    }

    /**
     *
     * @return right part of the signature
     */
    public final String getRight() {
        return right;
    }

    @Override
    public final int hashCode() {
        int hash = 5;
        hash = 83 * hash + this.blocksize;
        hash = 83 * hash + (this.left != null ? this.left.hashCode() : 0);
        hash = 83 * hash + (this.right != null ? this.right.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Signature other = (Signature) obj;
        if (this.blocksize != other.blocksize) {
            return false;
        }
        if ((this.left == null) ? (other.left != null) : !this.left.equals(other.left)) {
            return false;
        }
        if ((this.right == null) ? (other.right != null) : !this.right.equals(other.right)) {
            return false;
        }
        return true;
    }


}
