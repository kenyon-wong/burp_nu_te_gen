## 执行模式：CI/CD 自动化（无人值守）

**环境**：GitHub Actions，无用户交互，所有操作自动批准（`--dangerously-skip-permissions`）。

**退出检查**：如果 `.agent/completed` 文件存在，立即退出（防止重复执行）。

## TODO list:

1. 我希望基于 montoya-api 重写此项目
   - java 版本限定为 jdk 17
   - 必须全部使用 montoya 接口，绝对禁止使用传统burp API
   - 必须使用 maven 作为当前项目的唯一，不允许使用 gradle、ant等
   - 项目必须遵循 maven 的最佳实践，包括 pom.xml、目录组织结构等
   - 基于 Burp Montoya 原生接口使用，深色主题适配
   - 需要洞察需求本质，正确设计数据结构，避免“数据双头拥有”反模式的问题
   - 需要避免中文字符编码出现乱码问题
   - UI 布局样式要统一，自适应，稳定
   - POM 规范：
      - Java 17 作为默认与强制编译版本
      - compiler 开启 -parameters、显示并收敛警告
      - resources 过滤启用
      - shade 仅产出一个最终 jar，并进行常见依赖 relocation 与过滤
      - pluginManagement 明确版本，enforcer 校验环境
   - 正则表达式需要预编译使用
   - 遵循"Linus式"开发原则：简洁、实用、无破坏性改动
   - 结果表格宽度自适应：结果表格中，字段的宽度需要按照比例来调整，从而适应不同分辨率，不要硬编码，自动铺满，所有字段宽度之和应该100%，确保左右空间都充分利用
   - 需要洞察需求本质，正确设计数据结构，避免“数据双头拥有”反模式的问题
   - 实现数据绑定机制，UI自动同步
   - 使用观察者模式避免手动同步

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
