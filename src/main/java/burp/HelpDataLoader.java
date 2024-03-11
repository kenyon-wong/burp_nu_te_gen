package burp;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class HelpDataLoader {
    public static String loadHelpData(String resourcePath) {
        try (InputStream inputStream = HelpDataLoader.class.getResourceAsStream(resourcePath);
             Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8.name())) {
            return scanner.useDelimiter("\\A").next();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load help data from resource: " + resourcePath, e);
        }
    }
}
