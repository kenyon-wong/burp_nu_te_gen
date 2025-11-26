package burp.model;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * 匹配器配置 - 不可变对象
 * 使用 EnumSet 替代多个 boolean 字段,符合 Linus "好品味"原则
 */
public record MatcherConfig(Set<MatcherType> enabledMatchers) {

    /**
     * 匹配器类型枚举
     */
    public enum MatcherType {
        WORD,
        HEADER,
        STATUS,
        NEGATIVE,
        TIME,
        SIZE,
        INTERACTSH_PROTOCOL,
        INTERACTSH_REQUEST,
        REGEX,
        BINARY,
        EXTRACTORS
    }

    /**
     * 紧凑构造器 - 确保不可变性
     */
    public MatcherConfig {
        enabledMatchers = Collections.unmodifiableSet(EnumSet.copyOf(enabledMatchers));
    }

    /**
     * 创建默认配置(所有匹配器关闭)
     */
    public static MatcherConfig createDefault() {
        return new MatcherConfig(EnumSet.noneOf(MatcherType.class));
    }

    /**
     * 从 EnumSet 创建配置
     */
    public static MatcherConfig of(MatcherType... types) {
        if (types.length == 0) {
            return createDefault();
        }
        return new MatcherConfig(EnumSet.of(types[0], types));
    }

    /**
     * 检查是否启用特定匹配器
     */
    public boolean isEnabled(MatcherType type) {
        return enabledMatchers.contains(type);
    }

    /**
     * 检查是否有任何匹配器启用(排除 EXTRACTORS)
     */
    public boolean hasAnyMatcher() {
        return enabledMatchers.stream()
            .anyMatch(t -> t != MatcherType.EXTRACTORS);
    }

    /**
     * 检查是否启用提取器
     */
    public boolean hasExtractors() {
        return enabledMatchers.contains(MatcherType.EXTRACTORS);
    }
}
