package burp.model;

/**
 * 不可变的模板配置对象
 * 使用 Java 17 record 特性,自动生成构造器、getter、equals、hashCode
 */
public record TemplateConfig(
    String id,
    String name,
    String author,
    Severity severity,
    String description,
    String tags,
    RequestMethod method,
    String path,
    ContentType contentType,
    String body,
    boolean followRedirects,
    int maxRedirects,
    MatcherConfig matchers
) {
    /**
     * 严重程度枚举
     */
    public enum Severity {
        INFO, LOW, MEDIUM, HIGH, CRITICAL
    }

    /**
     * HTTP 请求方法
     */
    public enum RequestMethod {
        GET, POST, PUT, DELETE, OPTIONS, TRACE, RAW
    }

    /**
     * Content-Type 类型
     */
    public enum ContentType {
        NONE(""),
        URL_ENCODED("application/x-www-form-urlencoded"),
        JSON("application/json"),
        XML("text/xml");

        private final String mValue;

        ContentType(String value) {
            this.mValue = value;
        }

        public String getValue() {
            return mValue;
        }
    }

    /**
     * 紧凑构造器 - 参数验证
     */
    public TemplateConfig {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("Template ID cannot be empty");
        }
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Template name cannot be empty");
        }
        if (maxRedirects < 0) {
            throw new IllegalArgumentException("Max redirects cannot be negative");
        }
    }
}
