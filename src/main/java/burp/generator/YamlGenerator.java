package burp.generator;

import burp.model.MatcherConfig;
import burp.model.TemplateConfig;

/**
 * 纯函数式 YAML 生成器
 * 所有方法都是静态无副作用函数
 */
public final class YamlGenerator {

    private YamlGenerator() {
        throw new AssertionError("Utility class should not be instantiated");
    }

    /**
     * 生成完整的 Nuclei YAML 模板
     *
     * @param config 模板配置
     * @return YAML 字符串
     */
    public static String generate(TemplateConfig config) {
        StringBuilder yaml = new StringBuilder();

        yaml.append(generateMetadata(config));
        yaml.append(generateHttpSection(config));

        if (config.matchers().hasAnyMatcher()) {
            yaml.append(generateMatchers(config.matchers()));
        }

        if (config.matchers().useExtractors()) {
            yaml.append(generateExtractors());
        }

        return yaml.toString();
    }

    /**
     * 生成元数据部分
     */
    private static String generateMetadata(TemplateConfig config) {
        return String.format("""
            id: %s

            info:
              name: %s
              author: %s
              severity: %s
              description: |
                %s
              metadata:
                fofa-query:
                shodan-query:
                hunter-query:
              reference:
                - https://
              tags: %s

            """,
            config.id(),
            config.name(),
            config.author(),
            config.severity().name().toLowerCase(),
            config.description(),
            config.tags()
        );
    }

    /**
     * 生成 HTTP 请求部分
     */
    private static String generateHttpSection(TemplateConfig config) {
        StringBuilder http = new StringBuilder();

        if (config.method() == TemplateConfig.RequestMethod.RAW) {
            http.append(generateRawRequest(config));
        } else {
            http.append(generateStandardRequest(config));
        }

        if (config.followRedirects()) {
            http.append(String.format("""
                    host-redirects: true
                    max-redirects: %d

                """, config.maxRedirects()));
        }

        return http.toString();
    }

    /**
     * 生成 RAW 请求格式
     */
    private static String generateRawRequest(TemplateConfig config) {
        String body = (config.body() != null && !config.body().isBlank())
            ? config.body()
            : "";

        return String.format("""
            http:
              - raw:
                  - |
                    POST %s HTTP/1.1
                    Host: {{Hostname}}
                    Content-Type: %s

                    %s

            """,
            config.path(),
            config.contentType().getValue(),
            body
        );
    }

    /**
     * 生成标准请求格式
     */
    private static String generateStandardRequest(TemplateConfig config) {
        StringBuilder req = new StringBuilder();

        req.append(String.format("""
            http:
              - method: %s
                path:
                  - "{{BaseURL}}%s"
            """,
            config.method().name(),
            config.path()
        ));

        if (config.contentType() != TemplateConfig.ContentType.NONE) {
            req.append(String.format("""
                    headers:
                      Content-Type: %s
            """, config.contentType().getValue()));
        }

        if (config.body() != null && !config.body().isBlank()) {
            req.append("""
                    body: |
                      替换此处注意每行缩进

            """);
        }

        return req.toString();
    }

    /**
     * 生成匹配器部分
     */
    private static String generateMatchers(MatcherConfig matchers) {
        StringBuilder m = new StringBuilder();
        m.append("""
                matchers-condition: and
                matchers:
        """);

        if (matchers.useWord()) {
            m.append("""
                  - type: word
                    part: body
                    words:
                      - 'test1'
                      - 'test2'
                    condition: or

        """);
        }

        if (matchers.useHeader()) {
            m.append("""
                  - type: word
                    part: header
                    words:
                      - 'tomcat'

        """);
        }

        if (matchers.useStatus()) {
            m.append("""
                  - type: status
                    status:
                      - 200

        """);
        }

        if (matchers.useNegative()) {
            m.append("""
                  - type: word
                    words:
                      - "荣耀立方"
                      - 'var model = "LW-N605R"'
                    part: body
                    negative: true
                    condition: or

        """);
        }

        if (matchers.useTime()) {
            m.append("""
                  - type: dsl
                    dsl:
                      - 'duration>=6'

        """);
        }

        if (matchers.useSize()) {
            m.append("""
                  - type: dsl
                    dsl:
                      - 'len(body)<130'

        """);
        }

        if (matchers.useInteractshProtocol()) {
            m.append("""
                  - type: word
                    part: interactsh_protocol
                    words:
                      - "http"

        """);
        }

        if (matchers.useInteractshRequest()) {
            m.append("""
                  - type: regex
                    part: interactsh_request
                    regex:
                      - "root:.*:0:0:"

        """);
        }

        if (matchers.useRegex()) {
            m.append("""
                  - type: regex
                    regex:
                      - "root:.*:0:0:"
                    part: body

        """);
        }

        if (matchers.useBinary()) {
            m.append("""
                  - type: binary
                    binary:
                      - "D0CF11E0"
                      - "53514C69746520"
                    part: body
                    condition: or

        """);
        }

        return m.toString();
    }

    /**
     * 生成提取器部分
     */
    private static String generateExtractors() {
        return """
                extractors:
                  - part: header
                    internal: true
                    group: 1
                    type: regex
                    regex:
                      - 'Set-Cookie: PHPSESSID=(.*); path=/'

        """;
    }
}
