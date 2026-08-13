# FceCore

<p align="center">
  <strong>基于 X.509 证书扩展密钥用法（EKU）的权限控制核心库</strong>
</p>

<p align="center">
  <a href="https://lsy041.com/OID/" target="_blank">📄 FCE OID 标准白皮书</a> | 
  <a href="https://github.com/lishi19990812/FceCore/releases" target="_blank">📥 下载发布版</a>
</p>

---

## 📖 项目简介

**FceCore** 是 [FCE OID Standard](https://lsy041.com/OID/) 的官方 C# 实现库。它提供了一套强力的权限校验机制，通过验证 X.509 证书中的自定义 OID（对象标识符），确保只有持有特定权限证书的用户才能执行加密、解密、签名等操作。

这不仅仅是一个加密库，更是一套**“权限与证书绑定”**的安全解决方案。

## 🔐 权限与操作对照表

在使用 FceCore 之前，请务必了解您的证书必须具备哪些 OID 才能执行特定操作。权限校验是本库的核心功能。

| 典型场景 | 操作动作 | 必需的 OID (Extended Key Usage) | 说明 |
| :--- | :--- | :--- | :--- |
| **加密文件** | `Encrypt()` | `1.3.6.1.4.1.60896.4.1.1`<br>(FCE Encrypt) | 只有持有此 OID 的证书才能加密数据（通常为数据发送方）。 |
| **解密文件** | `Decrypt()` | `1.3.6.1.4.1.60896.4.1.4`<br>(FCE Decrypt) | 只有持有此 OID 的证书才能解密数据（通常为数据接收方）。 |
| **数字签名** | `Sign()` | `1.3.6.1.4.1.60896.4.1.2`<br>(FCE Sign) | 授权对文件进行数字签名。 |
| **验证签名** | `Verify()` | `1.3.6.1.4.1.60896.4.1.3`<br>(FCE Verify) | 授权验证数字签名的有效性。 |

> ⚠️ **注意**：如果证书中不包含对应操作的 OID，FceCore 将抛出 `FcePermissionException` 异常，操作将被终止。

## 🚀 快速开始

###  使用示例

在使用前，请确保证书已包含相应的 OID。
```
using FceCore;
using System.Security.Cryptography.X509Certificates;

// 初始化引擎
var engine = new FceEngine();
// 假设这里加载了一个包含 “加密权限(4.1.1)” 的证书
var senderCert = new X509Certificate2(“path/to/sender.pfx”, “password”);
try
{
// 尝试加密数据
// 底层会自动检查 cert 是否包含 “1.3.6.1.4.1.60896.4.1.1” OID
byte[] encryptedData = engine.Encrypt(dataToEncrypt, senderCert);
Console.WriteLine(“加密成功！数据已绑定权限。”);
}
catch (FcePermissionException ex)
{
// 权限不通过时捕获异常
Console.WriteLine($“权限校验失败: {ex.Message}”);
}
```

## 🛠️ 如何生成兼容的证书？

要使用本库，您的证书必须包含上述 **FCE OID**。Windows 原生工具（如 PowerShell）或 OpenSSL 均可生成。

以下提供几种常见角色的证书生成命令，您可以直接复制使用。

### 1. 生成“发送者”证书（含加密与签名权限）
适用于需要加密并发送文件、或者需要对文件进行签名的用户。
powershell
```
#定义 OID 变量
 EncryptOID="1.3.6.1.4.1.60896.4.1.1"SignOID = “1.3.6.1.4.1.60896.4.1.2”
#组合 EKU 字符串 (注意：2.5.29.37 是 EKU 扩展的 OID)
EkuString="2.5.29.37=textEkuString="2.5.29.37=textDecryptOID,$VerifyOID"
New-SelfSignedCertificate -Subject "CN=FCE_Sender_041" -CertStoreLocation “Cert:\CurrentUser\My” -TextExtension $EkuString -KeyUsage KeyEncipherment, DigitalSignature
```
### 2. 生成“接收者”证书（含解密与验证权限）
适用于需要接收并解密文件、或者需要验证他人签名的用户。
powershell
```
#定义 OID 变量
DecryptOID="1.3.6.1.4.1.60896.4.1.3"VerifyOID = “1.3.6.1.4.1.60896.4.1.4”
#组合 EKU 字符串
EkuString="2.5.29.37=textEkuString="2.5.29.37=textDecryptOID,$VerifyOID"
New-SelfSignedCertificate -Subject "CN=FCE_Receiver_041" -CertStoreLocation “Cert:\CurrentUser\My” -TextExtension $EkuString -KeyUsage KeyEncipherment, DigitalSignature
### 3. 生成“全能”测试证书（包含所有权限）
仅用于测试环境，方便调试。
```
### 3. 生成“全能”测试证书（包含所有权限）
仅用于测试环境，方便调试。
powershell
```
#组合所有 OID
$AllOids = “1.3.6.1.4.1.60896.4.1.1,1.3.6.1.4.1.60896.4.1.2,1.3.6.1.4.1.60896.4.1.3,1.3.6.1.4.1.60896.4.1.4”
New-SelfSignedCertificate -Subject "CN=FCE_Admin_Test" -CertStoreLocation “Cert:\CurrentUser\My”  -TextExtension @("2.5.29.37={text}$AllOids") -KeyUsage KeyEncipherment, DigitalSignature
```
生成证书后，您可以在证书详情的“增强型密钥用法” 属性中看到对应的 OID 数字串。

## 📜 开源协议与免责声明

本项目采用 **MIT** 协议开源。

**重要声明：**
- 本库遵循 **[FCE OID 标准](https://lsy041.com/OID/)**，使用者需遵守该标准的法律免责声明。
- 本库仅提供技术实现，使用者需自行承担使用本库进行任何操作的法律责任。
- 严禁将本库用于任何违反法律法规的场景。

## 📧 联系方式

- **维护者**: 041专属
- **Email**: myanemis041@vip.qq.com
- **GitHub**: [https://github.com/lishi19990812](https://github.com/lishi19990812)











