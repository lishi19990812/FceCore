using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace FceCore
{
    /// <summary>
    /// FCE 加密引擎核心类
    /// </summary>
    public static class FceEngine
    {
        /// <summary>
        /// 加密并签名数据
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="recipientCerts">接收者证书列表（仅需公钥）</param>
        /// <param name="signerCert">签名者证书（需私钥）</param>
        /// <param name="type">文件类型：0=单文件，1=文件包</param>
        /// <returns>包含FCE文件头的加密数据</returns>
        public static byte[] Encrypt(byte[] data, List<X509Certificate2> recipientCerts, X509Certificate2 signerCert, int type = 0)
        {
            // 1. 参数检查
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空");
            if (recipientCerts == null || recipientCerts.Count == 0)
                throw new ArgumentException("至少需要一个接收者");
            if (signerCert == null)
                throw new ArgumentException("签名者证书不能为空");

            // 2. 权限预检
            if (!FceOids.CanEncrypt(signerCert))
            {
                string perm = FceOids.GetCertPermissions(signerCert);
                throw new FcePermissionException(
                    $"签名者证书权限不足。需要：{FceOids.Encrypt} + {FceOids.Sign}",
                    "FCE加密 + FCE签名",
                    perm
                );
            }

            // 3. CMS 加密
            var envelopedCms = new EnvelopedCms(new ContentInfo(data));
            var recipients = new CmsRecipientCollection();
            foreach (var cert in recipientCerts)
                recipients.Add(new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, cert));

            envelopedCms.Encrypt(recipients);
            byte[] encryptedData = envelopedCms.Encode();

            // 4. CMS 签名
            var signedCms = new SignedCms(new ContentInfo(encryptedData));
            var signer = new CmsSigner(signerCert)
            {
                DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1") // SHA256
            };
            signedCms.ComputeSignature(signer);
            byte[] signedData = signedCms.Encode();

            // 5. 包装文件头
            return FceFileFormat.Wrap(signedData, type);
        }

        /// <summary>
        /// 验证并解密数据
        /// </summary>
        /// <param name="fceData">FCE加密文件数据</param>
        /// <param name="decryptorCert">解密者证书（需私钥）</param>
        /// <returns>解密后的原始数据</returns>
        public static byte[] Decrypt(byte[] fceData, X509Certificate2 decryptorCert)
        {
            // 1. 参数检查
            if (fceData == null)
                throw new ArgumentException("数据不能为空");
            if (decryptorCert == null)
                throw new ArgumentException("解密证书不能为空");

            // 2. 权限预检
            if (!FceOids.CanDecrypt(decryptorCert))
            {
                string perm = FceOids.GetCertPermissions(decryptorCert);
                throw new FcePermissionException(
                    $"解密者证书权限不足。需要：{FceOids.Decrypt} + {FceOids.Verify}",
                    "FCE解密 + FCE验证",
                    perm
                );
            }

            // 3. 解除文件包装 (捕获底层异常并转换)
            byte[] signedData;
            try
            {
                signedData = FceFileFormat.Unwrap(fceData);
            }
            catch (InvalidDataException ex)
            {
                throw new FceFileFormatException("文件格式无效或已损坏。", ex);
            }

            // 4. 验证签名
            var signedCms = new SignedCms();
            signedCms.Decode(signedData);
            try
            {
                signedCms.CheckSignature(true);
            }
            catch (CryptographicException ex)
            {
                throw new FceCryptographicException("签名验证失败！文件可能被篡改。", ex);
            }

            // 5. 准备解密
            var envelopedCms = new EnvelopedCms();
            envelopedCms.Decode(signedCms.ContentInfo.Content);

            // 预检：检查接收者列表中是否包含当前证书，避免弹出无关密码框
            bool isRecipient = false;
            foreach (var info in envelopedCms.RecipientInfos)
            {
                if (info.RecipientIdentifier.MatchesCertificate(decryptorCert))
                {
                    isRecipient = true;
                    break;
                }
            }
            if (!isRecipient)
            {
                throw new FceCryptographicException("当前证书不在该文件的接收者列表中。");
            }

            // 6. 执行解密
            try
            {
                envelopedCms.Decrypt(new X509Certificate2Collection(decryptorCert));
            }
            catch (CryptographicException ex)
            {
                throw new FceCryptographicException("解密失败，私钥权限不足或数据损坏。", ex);
            }

            return envelopedCms.ContentInfo.Content;
        }
    }
}
