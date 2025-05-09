package burp.utils;

import java.util.ArrayList;

/**
 * 配置工具类
 * 提供配置常量、枚举和其他配置相关的实用方法
 */
public class ConfigUtils {
    
    /**
     * 重定向模式
     */
    public enum RedirectsMode {
        istrue, isfalse
    }

    /**
     * 内容类型模式
     */
    public enum ContentTypeMode {
        不使用, urlencoded, json, xml
    }

    /**
     * 内容主体模式
     */
    public enum ContentBodyMode {
        不带, 带
    }

    /**
     * 严重程度模式
     */
    public enum SeverityMode {
        info, low, medium, high, critical
    }

    /**
     * 请求方式
     */
    public enum ReqMode {
        GET, POST, RAW, PUT, OPTIONS, TRACE
    }
    
    /**
     * 将枚举值转换为字符串数组
     * @param enumValues 枚举值数组
     * @return 格式化的字符串数组
     */
    public static <T extends Enum<?>> String[] enumToStringArray(T[] enumValues) {
        ArrayList<String> strings = new ArrayList<>();
        for (T value : enumValues) {
            strings.add(value.name().replace('_', '/'));
        }
        return strings.toArray(new String[0]);
    }
    
    /**
     * 获取请求方式列表
     */
    public static String[] getReqModes() {
        return enumToStringArray(ReqMode.values());
    }
    
    /**
     * 获取严重程度列表
     */
    public static String[] getSeverityModes() {
        return enumToStringArray(SeverityMode.values());
    }
    
    /**
     * 获取Body模式列表
     */
    public static String[] getBodyModes() {
        return enumToStringArray(ContentBodyMode.values());
    }
    
    /**
     * 获取Content-Type列表
     */
    public static String[] getHeadersModes() {
        return enumToStringArray(ContentTypeMode.values());
    }
    
    /**
     * 获取重定向模式列表
     */
    public static String[] getRedirectsModes() {
        return enumToStringArray(RedirectsMode.values());
    }
    
    /**
     * 格式化Content-Type
     * 将枚举值转换为HTTP Header使用的格式
     */
    public static String formatContentType(String contentType) {
        if ("urlencoded".equals(contentType)) {
            return "application/x-www-form-urlencoded";
        } else if ("json".equals(contentType)) {
            return "application/json";
        } else if ("xml".equals(contentType)) {
            return "text/xml";
        }
        return contentType;
    }
}
