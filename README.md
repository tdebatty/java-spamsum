#java-spamsum

A Java implementation of SpamSum, also known as SSDeep or Context Triggered Piecewise Hashing (CTPH), based on the original [SpamSum program by Andrew Tridgell](http://www.samba.org/ftp/unpacked/junkcode/spamsum/).


## Download
Using maven:
```
<dependency>
    <groupId>info.debatty</groupId>
    <artifactId>java-spamsum</artifactId>
    <version>RELEASE</version>
</dependency>
```

See the [releases](https://github.com/tdebatty/java-spamsum/releases) page.

## Usage

```java
import info.debatty.java.spamsum.*;

public class MyApp {
    
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
}
```

