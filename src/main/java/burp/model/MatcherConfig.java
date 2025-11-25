package burp.model;

import java.util.List;

/**
 * 匹配器配置 - 不可变对象
 */
public record MatcherConfig(
    boolean useWord,
    boolean useHeader,
    boolean useStatus,
    boolean useNegative,
    boolean useTime,
    boolean useSize,
    boolean useInteractshProtocol,
    boolean useInteractshRequest,
    boolean useRegex,
    boolean useBinary,
    boolean useExtractors
) {
    /**
     * 创建默认配置(所有匹配器关闭)
     */
    public static MatcherConfig createDefault() {
        return new MatcherConfig(
            false, false, false, false, false,
            false, false, false, false, false, false
        );
    }

    /**
     * 检查是否有任何匹配器启用
     */
    public boolean hasAnyMatcher() {
        return useWord || useHeader || useStatus || useNegative || useTime
            || useSize || useInteractshProtocol || useInteractshRequest
            || useRegex || useBinary;
    }
}
