package burp.model;

/**
 * Template configuration data model
 * Stores configuration for Nuclei template generation
 */
public class TemplateConfig {
    private String id;
    private String name;
    private String author;
    private String description;
    private String tags;
    private String severity;
    private String requestType;
    private String path;
    private String contentType;
    private String body;
    private String isRedirect;
    private String redirectNum;
    
    // Matcher configurations
    private boolean matchWord;
    private boolean matchHeader;
    private boolean matchStatus;
    private boolean matchNegative;
    private boolean matchTime;
    private boolean matchSize;
    private boolean matchInteractshProtocol;
    private boolean matchInteractshRequest;
    private boolean matchRegex;
    private boolean matchBinary;
    private boolean extractors;
    
    public TemplateConfig() {
        // Set default values
        this.id = "test";
        this.name = "test";
        this.author = "ffffffff0x";
        this.description = "由插件自动生成";
        this.tags = "auto";
        this.severity = "info";
        this.requestType = "GET";
        this.path = "";
        this.contentType = "不使用";
        this.body = "不带";
        this.isRedirect = "isfalse";
        this.redirectNum = "0";
        
        // Initialize all matchers to false by default
        resetAllMatchers();
    }
    
    /**
     * Reset all matchers to default state
     */
    public void resetAllMatchers() {
        this.matchWord = false;
        this.matchHeader = false;
        this.matchStatus = false;
        this.matchNegative = false;
        this.matchTime = false;
        this.matchSize = false;
        this.matchInteractshProtocol = false;
        this.matchInteractshRequest = false;
        this.matchRegex = false;
        this.matchBinary = false;
        this.extractors = false;
    }
    
    /**
     * Check if any matcher is selected
     * @return true if at least one matcher is selected
     */
    public boolean hasAnyMatcherSelected() {
        return matchWord || matchHeader || matchStatus || matchNegative || matchTime || 
               matchSize || matchInteractshProtocol || matchInteractshRequest || 
               matchRegex || matchBinary || extractors;
    }

    // Getters and setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getTags() {
        return tags;
    }

    public void setTags(String tags) {
        this.tags = tags;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getRequestType() {
        return requestType;
    }

    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public String getIsRedirect() {
        return isRedirect;
    }

    public void setIsRedirect(String isRedirect) {
        this.isRedirect = isRedirect;
    }

    public String getRedirectNum() {
        return redirectNum;
    }

    public void setRedirectNum(String redirectNum) {
        this.redirectNum = redirectNum;
    }

    public boolean isMatchWord() {
        return matchWord;
    }

    public void setMatchWord(boolean matchWord) {
        this.matchWord = matchWord;
    }

    public boolean isMatchHeader() {
        return matchHeader;
    }

    public void setMatchHeader(boolean matchHeader) {
        this.matchHeader = matchHeader;
    }

    public boolean isMatchStatus() {
        return matchStatus;
    }

    public void setMatchStatus(boolean matchStatus) {
        this.matchStatus = matchStatus;
    }

    public boolean isMatchNegative() {
        return matchNegative;
    }

    public void setMatchNegative(boolean matchNegative) {
        this.matchNegative = matchNegative;
    }

    public boolean isMatchTime() {
        return matchTime;
    }

    public void setMatchTime(boolean matchTime) {
        this.matchTime = matchTime;
    }

    public boolean isMatchSize() {
        return matchSize;
    }

    public void setMatchSize(boolean matchSize) {
        this.matchSize = matchSize;
    }

    public boolean isMatchInteractshProtocol() {
        return matchInteractshProtocol;
    }

    public void setMatchInteractshProtocol(boolean matchInteractshProtocol) {
        this.matchInteractshProtocol = matchInteractshProtocol;
    }

    public boolean isMatchInteractshRequest() {
        return matchInteractshRequest;
    }

    public void setMatchInteractshRequest(boolean matchInteractshRequest) {
        this.matchInteractshRequest = matchInteractshRequest;
    }

    public boolean isMatchRegex() {
        return matchRegex;
    }

    public void setMatchRegex(boolean matchRegex) {
        this.matchRegex = matchRegex;
    }

    public boolean isMatchBinary() {
        return matchBinary;
    }

    public void setMatchBinary(boolean matchBinary) {
        this.matchBinary = matchBinary;
    }

    public boolean isExtractors() {
        return extractors;
    }

    public void setExtractors(boolean extractors) {
        this.extractors = extractors;
    }
}
