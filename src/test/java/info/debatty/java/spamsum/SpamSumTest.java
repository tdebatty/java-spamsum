/*
 * The MIT License
 *
 * Copyright 2016 Thibault Debatty.
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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 *
 * @author Thibault Debatty
 */
public class SpamSumTest {


    /**
     * Test of match method, of class SpamSum.
     */
    @Test
    public void testMatch() throws IOException {
        System.out.println("Match");
        /*
        ssdeep -bm hashes.txt loremipsum.txt
        loremipsum.txt matches hashes.txt:loremipsum2.txt (85)
        */

        SpamSum spamsum = new SpamSum();

        String li1 = readResourceFile("loremipsum.txt");
        String li2 = readResourceFile("loremipsum2.txt");

        assertEquals(
                85,
                spamsum.match(
                        spamsum.HashString(li1),
                        spamsum.HashString(li2)));
    }

    @Test
    public void testHashString() {
        System.out.println("hash");
        SpamSum instance = new SpamSum();

        String expResult = "3:Y0ujLEEz6KxMENJv:Y0u3tz68/v";
        String result = instance.HashString("Play to win  Download Casino King Spin now\n");
        assertEquals(expResult, result);

        expResult = "3:hMCEqNE0M+YFFWV5wdgHMyA8FNzs1b:hujkYFFWV51HM8Lzs1b";
        result = instance.HashString("This is a string that might be a spam... Depends on the "
                + "hash, if it looks like a known hash...\n");
        assertEquals(expResult, result);
    }

    @Test
    public void testHashFile() throws IOException {
        /*
        ssdeep -b *
        ssdeep,1.1--blocksize:hash:hash,filename
        48:9GCjd6ALqt7+svFIHO4CJ4foXT5aKDbyb4XDFN40shD7iqRJCLoz6a8s+U7f+4kh:9vvqt7+sUO4CKAXTgKDbRXDFOl7FRJAD,"loremipsum2.txt"
        48:9zdDCjd6ALqt7+svFIHO4VHCJ4foXT5Luz5b4XDFN40shD7iqRJCLoz6a8s+U7fe:9zMvqt7+sUO4NCKAXT5LuzSXDFOl7FRw,"loremipsum.txt"
        */

        SpamSum spamsum = new SpamSum();
        String li1 = readResourceFile("loremipsum.txt");
        assertEquals(
                "48:9zdDCjd6ALqt7+svFIHO4VHCJ4foXT5Luz5b4XDFN40shD7iqRJCLoz6a8s+U7fe:9zMvqt7+sUO4NCKAXT5LuzSXDFOl7FRw",
                spamsum.HashString(li1));

        String li2 = readResourceFile("loremipsum2.txt");
        assertEquals(
                "48:9GCjd6ALqt7+svFIHO4CJ4foXT5aKDbyb4XDFN40shD7iqRJCLoz6a8s+U7f+4kh:9vvqt7+sUO4CKAXTgKDbRXDFOl7FRJAD",
                spamsum.HashString(li2));

    }

    private static String readResourceFile(String file) throws IOException {

        InputStream stream = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream(file);

        BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
        StringBuilder string_builder = new StringBuilder();
        String ls = System.getProperty("line.separator");
        String line = null;

        while (( line = reader.readLine() ) != null ) {
            string_builder.append(line);
            string_builder.append(ls);
        }

        // don't delete the final "\n"
        //string_builder.deleteCharAt(string_builder.length() - 1);
        return string_builder.toString();
    }

}
