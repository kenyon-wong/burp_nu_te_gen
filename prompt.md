## 执行模式：CI/CD 自动化（无人值守）

**环境**：GitHub Actions，无用户交互，所有操作自动批准（`--dangerously-skip-permissions`）。

**退出检查**：如果 `.agent/completed` 文件存在，立即退出（防止重复执行）。

## TODO list:

## 1. **构建与依赖管理**

   - **强制使用 Maven 构建**：保持纯粹、规范的 Maven 项目，不允许 Gradle 或其他工具，以确保构建一致性。理由：Maven 在 Burp 插件生态中更常见，便于集成 Burp 的 Maven 插件。
   - **POM 规范**：
     - 默认 Java 17 作为编译版本（使用 `<java.version>17</java.version>`）。
     - Compiler 插件配置：启用 `-parameters`（便于反射访问参数名）、显示所有警告并使用 `<failOnWarning>true</failOnWarning>` 收敛它们。
     - Resources 过滤启用（`<filtering>true</filtering>`），以支持配置文件变量替换。
     - 使用 Maven Shade 插件产出单一 JAR：进行依赖 relocation（e.g., 常见库如 Guava 移到自定义包路径，避免与 Burp 冲突），并过滤不必要的文件（如 META-INF/*.SF）。
     - PluginManagement 明确插件版本，Enforcer 插件校验环境（e.g., JDK 版本、OS）。
     - 依赖管理使用 `<dependencyManagement>` 控制版本，避免漏洞（定期扫描如使用 Dependency-Check 插件）。
   - **打包输出**：仅一个最终 JAR，确保插件加载时无冲突。

## 2. **代码风格与原则**

   - **API 使用**：必须全部使用 Montoya API，绝对禁止传统 Burp API。理由：Montoya 更现代、安全，支持线程安全和未来更新。
   - **编码规范**：避免数据包中中文字符编码乱码（使用 UTF-8 一致编码，e.g., `Charset.forName("UTF-8")`）。
   - **正则表达式**：必须预编译使用（e.g., `Pattern.compile()` 静态初始化），以提升性能。
   - **设计原则**：
     - 遵循“Linus 式”原则：代码简洁、实用、无破坏性改动（e.g., 优先小函数、避免大重构）。
     - 洞察需求本质，正确设计数据结构，避免“数据双头拥有”反模式（e.g., 使用单一所有者模型，避免多个类同时持有可变数据引用）。
     - 修改代码前，确认复用现有逻辑，从根源减少重复代码（e.g., 使用 IDE 的“Find Usages”检查）。
     - **新增**：遵循 SOLID 原则，特别是单一职责和开闭原则。使用 Lombok 简化 boilerplate（如@Getter/@Setter），但避免过度。
   - **反射与 Mock**：克制使用反射（仅限必要，如动态加载），避免 Mock 滥用（优先真实集成测试）。
   - **日志与错误处理**：使用 SLF4J 日志框架，记录关键事件。实现全局异常处理（e.g., Montoya 的回调中捕获 Throwable），提供用户友好错误消息。

## 3. **UI 与用户体验**

   - **布局规范**：UI 统一、自适应、稳定（使用 Swing 或 JavaFX 组件，确保布局管理器如 BorderLayout/GridBagLayout 支持 resize）。
   - **结果表格**：宽度自适应，按比例调整（e.g., 使用 TableColumnModel 设置百分比宽度，总和 100%），自动铺满，确保在不同分辨率下充分利用空间，避免硬编码像素值。
   - **数据绑定**：实现机制，使 UI 自动同步（e.g., 使用 PropertyChangeSupport）。
   - **观察者模式**：用于避免手动同步（e.g., Montoya 的 EventListener 接口）。
   - **i18n 支持**：实现多语言（使用 ResourceBundle，键值文件支持 UTF-8）。
   - **深色模式适配**：基于 Montoya API，实现主题切换（e.g., 检查 Burp 的 UI 主题并调整颜色）。
   - **新增**：Accessibility 支持（e.g., 添加 Alt 文本、键盘导航），确保插件在 Burp 的 Tab 中无缝集成。

## 4. **文档与元信息**

   - **统一元信息**：在插件主类中添加：
     ```bash
     @author kenyon
     @mail kenyon <kenyon@noreply.localhost>
     ```
     **新增**：包括版本、描述、许可（e.g., MIT 或 GPL）。
   - **CHANGELOG.md**：遵循 Keep a Changelog 格式（sections 如 Added/Changed/Fixed）。
   - **示例代码管理**：审查必要性，倾向移除转为内联注释（e.g., Javadoc 中示例）。避免在项目中添加 bash/Python 测试脚本，转由 GitHub Actions 自动化。
   - **目录组织**：规范测试与示例代码目录（e.g., src/main/java 为生产代码，src/test/java 为单元测试），避免混放。
   - **新增**：README.md 包括安装指南、配置示例、截图。使用 Javadoc 生成 API 文档。

## 5. **测试与 CI/CD**

   - **测试框架**：使用 JUnit 5 进行单元/集成测试，覆盖率目标 80% 以上。Mock Montoya API 时使用官方提供的测试工具或 Mockito（但克制）。
   - **自动化**：所有测试/构建由 GitHub Actions 完成（e.g., Maven 构建、静态分析如 SpotBugs）。
   - **新增**：性能测试（e.g., 插件在高负载下的响应时间），安全扫描（避免硬编码凭证）。

## 6. **铁律（核心不可违背规则）**

   1. **示例代码精简**：审查必要性，优先移除转为内联注释/Javadoc。示例只会增加维护复杂度，除非用于复杂 API 演示。
   2. **测试组织**：规范目录，避免与主源码混放。测试工作自动化到 CI（如 GitHub Actions），禁止手动脚本。
   3. **避免滥用**：克制反射/Mock，仅在无法避免时使用。优先真实环境测试。
   4. **新增**：版本兼容性：插件必须在最新 Burp 版本测试，避免依赖未文档化的行为。
   5. **新增**：安全第一：插件不得引入漏洞（如未验证输入导致注入），定期审计代码。

1. **异常处理要覆盖整个方法体** - 不要只包裹关键操作
2. **不可修改集合要正确使用** - 改用 `setXxx(new HashSet<>())` 而不是 `.clear()`
3. **Lambda 表达式会吞掉异常** - 必须在 handler 内部捕获并记录
4. **UI 事件调试要系统化** - 从外到内逐层确认执行路径
5. **单元测试要覆盖异常路径** - 不要只测试 happy path

最佳实践

1. ✅ 整个 UI 事件处理方法都包裹在 try-catch 中
2. ✅ 集合修改使用 setter 而不是直接操作 getter 返回值
3. ✅ 所有异常都要记录详细信息并通知用户
4. ✅ 使用弹窗/日志逐步诊断代码执行路径
5. ✅ 为边界情况和异常路径编写单元测试
6. ✅ 建立代码审查清单，避免类似问题

**如果 TODO list 为空或选择暂停**：创建 `.agent/completed` 文件并退出。

## 执行规则:

### Workflow：
- 检查 `.agent/completed`，存在则退出
- TODO 为空：创建 `.agent/completed` 并退出
- TODO 非空：深度思考分析需求、设计数据结构、拆分任务
- 任务独立时并行执行，冲突时线性执行
- 每个任务完成后立即运行测试验证

### 工作规范：
- 使用 `.agent/` 存储计划和进度追踪
- 优先使用 mcp 和子代理处理独立任务
- 原子化变更，最小化修改范围
- 每个任务独立提交，便于问题定位和回滚
- CHANGELOG.md 遵循 Keep a Changelog 格式

### Git Commit 规范：
格式：`<type>(<scope>): <中文描述>`

类型：
- feat（新功能）
- fix（修复）
- docs（文档）
- refactor（重构）
- test（测试）
- chore（构建/工具）
- perf（性能优化）

**要求**：
- description 必须使用中文
- 禁止添加任何 AI 签名、footer 或 "Co-Authored-By"
- 描述要具体，说明改动内容和原因

示例：
- `refactor(logging): 合并emoji模块，减少文件碎片化`
- `chore(cleanup): 删除废弃的日志函数和未使用导入`
- `refactor(errors): 使用泛型trait消除错误处理函数重复`

### 测试验证：
每个任务完成后必须执行：
```bash
# 运行所有测试
cargo test --workspace

# 检查编译警告
cargo clippy --workspace --all-targets --all-features -- -D warnings

# 格式化检查
cargo fmt --all -- --check
```

### 完成后操作：
所有任务完成后：
1. 运行完整测试套件
2. 更新 `.agent/quality_improvement_summary.md` 添加本次执行结果
3. 执行 `git add . && git commit && git push`
4. 创建 `.agent/completed` 文件并退出

### 错误处理：
- 记录到 `.agent/errors.log`
- 如果测试失败，回滚变更并记录原因
- 继续下一任务，不要停止等待
- 如果连续3个任务失败，停止执行并报告

### 执行约束：
- 时间限制：6 小时
- 超时后提交已完成工作并退出
- 不要添加 TODO 外的任务
- 不要执行标记为"不执行"的高风险任务
