# Enhanced BurpGPT 使用指南 🚀
觉得好用请star~

## 这是什么？🤔
Enhanced BurpGPT 是一个 Burp Suite 插件，它能帮助你使用 AI（人工智能）来分析 Web 应用的安全问题。简单来说，当你测试网站时，你可以在指定的请求响应对，点击send to gpt，交由AI分析，找出潜在的安全漏洞。

## 警告⚠！看到ISSUE有很多小伙伴使用说无法发送/接受响应，经测试，大部分问题均因没有正确配置API接口和密钥，下面是主流厂商的API接口配置规范
### OpenAI
    API URL：https://api.openai.com/v1/chat/completions
### DeepSeek
    API URL：https://api.deepseek.com/v1/chat/completions
### 硅基流动siliconflow
    API URL：https://api.siliconflow.cn/v1/chat/completions
### Ollama
    API URL：http://ip:port/v1/chat/completions
    注意，Ollama的密钥要填写自己设置的密钥或者默认的密钥！

## 更新日志
### 2025-04-17
- **EnhancedBurpGPT2.5 SSL证书验证修复**
  ![image](https://github.com/user-attachments/assets/d99c0921-da4b-4b18-b50f-2960501a4cd1)
  - 添加了SSL证书验证控制选项，解决"java.security.cert.CertificateException: No certificate data found"错误
  - 在API设置面板中增加了"禁用SSL证书验证"选项，可以解决某些网络环境下的证书验证失败问题
  - 此设置可以帮助解决通过代理、公司网络或SSL检查设备连接API时出现的证书错误
### 2025-03-10
- **EnhancedBurpGPT2.0**
  - 修复**Error fetching models: cannot make memory view because object does not have thebuffer interface**此类通用错误。
    ![image](https://github.com/user-attachments/assets/c3718417-1ccf-4c40-8fad-dbbbbfa4a09c)

  
## 支持的模型厂家（仅列举部分厂家和模型）

### OpenAI
- **GPT-3.5-turbo**
  - 快速响应，性价比高
  - 适合日常测试使用
- **GPT-4**
  - 更强的分析能力
  - 适合复杂场景分析
- **o1-preview**
  - 最新的模型版本
  - 更大的上下文窗口
### Google
- **Gemini Pro**
  - 优秀的代码分析能力
- **Gemini-2.0-flash-thinking-exp**
  - 更强大的推理能力
  - 更好的多模态支持

### DeepSeek
- **DeepSeek-R1**
  - 开源模型支持
  - 本地部署选项
- **DeepSeek-Chat**
  - 优化的对话体验
  - 更好的中文支持

### Anthropic
- **claude-3.5-sonnet**
  - 优秀的理解能力
  - 优秀的代码能力
- **Claude 3 Haiku**
  - 更快的体验

### 几乎所有模型

## 为什么要用它？💡
- 自动化分析，节省时间
- AI 辅助发现安全问题
- 适合新手学习安全测试
- 提供详细的分析报告
- 支持中文输出
- 支持自定义prompt

## 使用截图

### 配置标签栏
![image](https://github.com/user-attachments/assets/aa5402ef-0064-4108-a864-6568159e6927)
比如我配置deepseek，即为：
![image](https://github.com/user-attachments/assets/8ed4ca42-aa89-4687-8914-1bc2b9dc8a38)


### 分析中截图
![image](https://github.com/user-attachments/assets/665db16b-9aeb-40f2-ad35-0d8f8a7471aa)


### 分析结果展示
![image](https://github.com/user-attachments/assets/06b1b75c-958b-47ba-b40f-74df9d1d8343)
Deepseek分析结果展示：
![image](https://github.com/user-attachments/assets/f3db239f-cca9-4132-ad01-515469f768aa)


## 安装步骤 📥

### 前提条件
- 已安装 Burp Suite
- 已安装 Jython（Python 环境）
- 有稳定的网络连接
- 有 GPT API 的密钥（API Key）

### 详细安装步骤
1. **安装 Jython**
   - 下载 [Jython Installer](https://www.jython.org/download.html)
   - 运行安装程序，记住安装路径

2. **配置 Burp Suite**
   - 打开 Burp Suite
   - 点击 `Extender` 标签
   - 点击 `Options` 子标签
   - 在 `Python Environment` 部分，选择你的 Jython jar 文件路径

3. **安装插件**
   - 在 Burp Suite 中，点击 `Extender` 标签
   - 点击 `Extensions` 子标签
   - 点击 `Add` 按钮
   - 选择 `Extension Type` 为 `Python`
   - 选择下载的 `burpGTPv1.py` 文件
   - 点击 `Next`，等待加载完成

## 配置教程 ⚙️

### 第一步：基础配置
1. 点击 `GPT Analysis` 标签
2. 在 `Configuration` 标签页中：
   - 填写 `API URL`（例如：`https://api.openai.com/v1/chat/completions`）
   - 填写你的 `API Key`
   - 选择或输入要使用的 `Model`（例如：`gpt-3.5-turbo`）
   - 注意，获取模型默认访问的是/v1/models，对话访问的是/v1/chat/completions

### 第二步：高级配置
1. **设置超时和长度限制**
   - `Timeout`：建议设置 60 秒
   - `Max Request Length`：建议设置 1000
   - `Max Response Length`：建议设置 2000

2. **自定义提示模板**
   - 可以使用默认模板
   - 也可以根据需要修改模板
   - 支持的变量：
     - `{URL}`：目标网址
     - `{METHOD}`：请求方法
     - `{REQUEST}`：请求内容
     - `{RESPONSE}`：响应内容

## 使用方法 🎯

### 基础使用
1. 在 Burp 的任意位置（如 Proxy、Repeater）右键点击请求
2. 选择 `Send to GPT`
3. 等待分析完成
4. 在 `Analysis Results` 标签页查看结果

### 查看结果
- 左侧显示分析历史列表
- 右侧显示详细分析内容
- 可以使用搜索功能查找历史记录
- 可以导出分析报告

### 查看日志
- 切换到 `Logs` 标签页
- 可以看到详细的操作记录
- 出现问题时可以查看错误信息

## 常见问题解答 ❓

### 1. 插件加载失败？
- 检查 Jython 是否正确安装
- 查看 `Extender` 的 `Errors` 标签页错误信息

### 2. 无法连接 API？
- 检查网络连接
- 验证 API URL 是否正确
- 确认 API Key 是否有效
- 检查代理设置

### 3. 分析结果为空？
- 检查请求/响应是否过大
- 确认模型选择是否正确
- 查看日志中的详细错误信息

### 4. 分析太慢？
- 调整超时时间设置
- 减小最大请求/响应长度
- 检查网络状况

## 使用技巧 💪

1. **提高分析效率**
   - 合理设置请求/响应长度限制
   - 使用自定义模板针对特定场景
   - 定期导出重要分析结果

2. **优化分析结果**
   - 调整提示模板以获得更精确的分析
   - 针对不同类型的请求使用不同的模板
   - 结合 Burp Suite 其他功能使用

3. **管理分析历史**
   - 及时清理不需要的分析记录
   - 使用搜索功能快速定位历史记录
   - 定期导出重要发现

## 注意事项 ⚠️

1. **安全性**
   - 不要分享你的 API Key
   - 注意请求/响应中的敏感信息
   - 定期更新插件版本

2. **资源使用**
   - 大量分析可能消耗 API 配额
   - 过多历史记录可能占用内存
   - 建议定期清理历史记录

3. **使用限制**
   - 部分功能需要网络连接
   - 分析结果仅供参考
   - 关闭 Burp Suite 后历史记录会清空

## 获取帮助 💬

如果遇到问题：
1. 查看日志信息
2. 检查配置是否正确
3. 尝试重启插件或 Burp Suite
4. [联系作者获取支持]

## 许可证 📄

本项目采用 [MIT 许可证](LICENSE)。
要求：
- ℹ️ 保留版权声明
- ℹ️ 保留许可证声明

## 免责声明 ⚠️

1. **使用责任**
   - ⚠️ 本工具仅用于安全测试和教育目的
   - ⚠️ 使用本工具进行任何测试都需获得测试目标的授权
   - ⚠️ 对未授权目标的任何测试行为与本工具作者无关
   - ⚠️ 使用者需对自己的行为负完全责任

2. **法律责任**
   - ⚠️ 使用者因使用本工具而触犯相关法律的，一切后果由使用者承担
   - ⚠️ 作者不对任何非法或未授权的测试行为承担责任
   - ⚠️ 作者不对使用本工具导致的任何直接或间接损失负责

3. **软件担保**
   - ⚠️ 本软件按"原样"提供，不提供任何形式的保证
   - ⚠️ 作者不承担任何明示或暗示的担保责任
   - ⚠️ 使用者需自行承担使用本软件的风险

4. **使用建议**
   - ✅ 建议在授权的测试环境中使用
   - ✅ 遵守相关法律法规和道德准则
   - ✅ 在使用前充分了解相关法律责任
   - ✅ 保存测试授权文件和相关证明

**请在使用本工具前仔细阅读并理解上述免责声明。使用本工具即表示您同意接受以上所有条款。如不同意，请勿使用本工具。**


## 未来计划 🚀

1. **被动扫描功能** 🔍
   - 添加被动扫描模式
   - 自动分析经过代理的请求
   - 可配置的扫描规则和过滤条件
   - 支持白名单和黑名单域名

2. **性能优化** ⚡
   - 优化请求处理逻辑
   - 添加请求队列管理
   - 实现并发分析功能
   - 改进内存使用效率
   
## Doing
代理功能开发中。。。。。
![image](https://github.com/user-attachments/assets/5a4db1b9-ca64-444d-9f7e-f56a30b4eee4)

- [ ] 加入代理选项


> 如果你有任何想法或建议，欢迎通过 Issue 或其他渠道与我交流！
