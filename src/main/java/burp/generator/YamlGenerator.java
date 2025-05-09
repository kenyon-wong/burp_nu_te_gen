package burp.generator;

import burp.model.TemplateConfig;
import burp.utils.ConfigUtils;
import java.io.InputStream;
import java.util.Scanner;
import java.nio.charset.StandardCharsets;

/**
 * YAML Generator
 * Responsible for generating Nuclei template YAML based on configuration
 */
public class YamlGenerator {
    
    // Template fragments
    private static final String ID_INFO = "id: %s\n" +
            "info:\n" +
            "  name: %s\n" +
            "  author: %s\n" +
            "  severity: %s\n" +
            "  description: |\n" +
            "    %s\n" +
            "  tags: %s\n\n";

    private static final String REQUESTS = "requests:\n" +
            "  - method: %s\n" +
            "    path:\n" +
            "      - '%s'\n";
            
    private static final String RAW_REQUESTS = "requests:\n" +
            "  - raw:\n" +
            "      - |\n" +
            "        GET %s HTTP/1.1\n" +
            "        Host: {{Hostname}}\n" +
            "        User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0\n" +
            "        Accept-Encoding: gzip, deflate\n" +
            "        Accept: */*\n" +
            "        Connection: close\n" +
            "        Content-Type: %s\n" +
            "        %s";
            
    private static final String HEADER = "    headers:\n" +
            "      Content-Type: %s\n";
            
    private static final String BODY = "    body: %s\n";
            
    private static final String REDIRECTS = "    redirects: %s\n";
            
    private static final String MATCHERS = "    matchers:\n";
            
    private static final String MATCHERS_WORD = "      - type: word\n" +
            "        words:\n" +
            "          - 'value'\n" +
            "        part: body\n\n";
            
    private static final String MATCHERS_HEADER = "      - type: word\n" +
            "        part: header\n" +
            "        words:\n" +
            "          - 'value'\n\n";
            
    private static final String MATCHERS_STATUS = "      - type: status\n" +
            "        status:\n" +
            "          - 200\n\n";
            
    private static final String MATCHERS_NEGATIVE = "      - type: word\n" +
            "        negative: true \n" +
            "        part: body\n" +
            "        words:\n" +
            "          - 'not found'\n" +
            "          - '404'\n\n";
            
    private static final String MATCHERS_TIME = "      - type: dsl\n" +
            "        dsl:\n" +
            "          - \"duration>=1 && duration<=3\"\n\n";
            
    private static final String MATCHERS_SIZE = "      - type: dsl\n" +
            "        dsl:\n" +
            "          - \"len(body)>=1024 && len(body)<=1028\"\n\n";
            
    private static final String MATCHERS_INTERACTSH_PROTOCOL = "      - type: word\n" +
            "        part: interactsh_protocol  # 配合 {{interactsh-url}} 关键词使用\n" +
            "        words:\n" +
            "          - \"http\"\n\n";
            
    private static final String MATCHERS_INTERACTSH_REQUEST = "      - type: regex\n" +
            "        part: interactsh_request   # 配合 {{interactsh-url}} 关键词使用\n" +
            "        regex:\n" +
            "          - \"root:.*:0:0:\"\n\n";
            
    private static final String MATCHERS_REGEX = "      - type: regex\n" +
            "        regex:\n" +
            "          - \"root:.*:0:0:\"\n" +
            "        part: body\n\n";
            
    private static final String MATCHERS_BINARY = "      - type: binary\n" +
            "        binary:\n" +
            "          - \"D0CF11E0\"  # db\n" +
            "          - \"53514C69746520\"  # SQLite\n" +
            "        part: body\n" +
            "        condition: or\n\n";
            
    private static final String EXTRACTORS = "    extractors:\n" +
            "      - part: header\n" +
            "        internal: true\n" +
            "        group: 1\n" +
            "        type: regex\n" +
            "        regex:\n" +
            "          - 'Set-Cookie: PHPSESSID=(.*); path=/'\n\n";
            
    /**
     * Generate YAML template from configuration
     * @param config Template configuration
     * @return Generated YAML string
     */
    public String generateYaml(TemplateConfig config) {
        StringBuilder yaml = new StringBuilder();
        
        // Add ID and info section
        yaml.append(String.format(ID_INFO, 
                config.getId(), 
                config.getName(), 
                config.getAuthor(), 
                config.getSeverity(), 
                config.getDescription(), 
                config.getTags()));
        
        // Handle request section based on request type
        if ("RAW".equals(config.getRequestType())) {
            // Process content type for RAW requests
            String contentType = ConfigUtils.formatContentType(config.getContentType());
            
            // Process body for RAW requests
            String body = config.getBody();
            if ("带".equals(body)) {
                body = "Body";
            } else if ("不带".equals(body)) {
                body = "";
            }
            
            yaml.append(String.format(RAW_REQUESTS, 
                    config.getPath(), 
                    contentType, 
                    body));
        } else {
            // Regular request
            yaml.append(String.format(REQUESTS, 
                    config.getRequestType(), 
                    config.getPath()));
            
            // Add headers based on content type
            String contentType = config.getContentType();
            if (!"不使用".equals(contentType)) {
                yaml.append(String.format(HEADER, ConfigUtils.formatContentType(contentType)));
            }
            
            // Add body if needed
            if (!"不带".equals(config.getBody())) {
                yaml.append(String.format(BODY, config.getBody()));
            }
        }
        
        // Add redirects configuration if enabled
        if ("istrue".equals(config.getIsRedirect())) {
            yaml.append(String.format(REDIRECTS, config.getRedirectNum()));
        }
        
        // Add first group of matchers
        appendFirstMatchersGroup(yaml, config);
        
        // Add second group of matchers
        appendSecondMatchersGroup(yaml, config);
        
        return yaml.toString();
    }
    
    /**
     * Append first group of matchers (word, header, status, negative, time)
     * @param yaml StringBuilder to append to
     * @param config Template configuration
     */
    private void appendFirstMatchersGroup(StringBuilder yaml, TemplateConfig config) {
        boolean hasAnyMatchers = config.isMatchWord() || config.isMatchHeader() || 
                                 config.isMatchStatus() || config.isMatchNegative() || 
                                 config.isMatchTime();
        
        if (hasAnyMatchers) {
            yaml.append(MATCHERS);
        }
        
        if (config.isMatchWord()) {
            yaml.append(MATCHERS_WORD);
        }
        
        if (config.isMatchHeader()) {
            yaml.append(MATCHERS_HEADER);
        }
        
        if (config.isMatchStatus()) {
            yaml.append(MATCHERS_STATUS);
        }
        
        if (config.isMatchNegative()) {
            yaml.append(MATCHERS_NEGATIVE);
        }
        
        if (config.isMatchTime()) {
            yaml.append(MATCHERS_TIME);
        }
    }
    
    /**
     * Append second group of matchers (size, interactsh, regex, binary, extractors)
     * @param yaml StringBuilder to append to
     * @param config Template configuration
     */
    private void appendSecondMatchersGroup(StringBuilder yaml, TemplateConfig config) {
        boolean needsMatchersHeader = !config.hasAnyMatcherSelected() && 
                                     (config.isMatchSize() || config.isMatchInteractshProtocol() || 
                                      config.isMatchInteractshRequest() || config.isMatchRegex() || 
                                      config.isMatchBinary());
        
        if (needsMatchersHeader) {
            yaml.append(MATCHERS);
        }
        
        if (config.isMatchSize()) {
            yaml.append(MATCHERS_SIZE);
        }
        
        if (config.isMatchInteractshProtocol()) {
            yaml.append(MATCHERS_INTERACTSH_PROTOCOL);
        }
        
        if (config.isMatchInteractshRequest()) {
            yaml.append(MATCHERS_INTERACTSH_REQUEST);
        }
        
        if (config.isMatchRegex()) {
            yaml.append(MATCHERS_REGEX);
        }
        
        if (config.isMatchBinary()) {
            yaml.append(MATCHERS_BINARY);
        }
        
        if (config.isExtractors()) {
            yaml.append(EXTRACTORS);
        }
    }
    
    /**
     * Load template from resource file
     * @param resourcePath Path to resource file
     * @return Content of resource file as string
     * @throws RuntimeException if resource cannot be loaded
     */
    public String loadTemplateFromResource(String resourcePath) {
        try (InputStream inputStream = YamlGenerator.class.getResourceAsStream(resourcePath)) {
            if (inputStream == null) {
                throw new RuntimeException("Template resource not found: " + resourcePath);
            }
            
            try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8.name())) {
                return scanner.useDelimiter("\\A").hasNext() ? scanner.next() : "";
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to load template resource: " + resourcePath, e);
        }
    }
}
