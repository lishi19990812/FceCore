using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FceCore
{
    /// <summary>
    /// 041专属 FCE 扩展密钥用法定义
    /// </summary>
    public static class FceOids
    {
        public const string FullAccess = "1.3.6.1.4.1.60896";
        public const string Encrypt = "1.3.6.1.4.1.60896.4.1.1";
        public const string Sign = "1.3.6.1.4.1.60896.4.1.2";
        public const string Verify = "1.3.6.1.4.1.60896.4.1.3";
        public const string Decrypt = "1.3.6.1.4.1.60896.4.1.4";

        public static string GetFriendlyName(string oid)
        {
            return oid switch
            {
                FullAccess => "FCE全部权限",
                Encrypt => "FCE加密",
                Sign => "FCE签名",
                Verify => "FCE验证",
                Decrypt => "FCE解密",
                _ => oid
            };
        }

        public static string GetCertPermissions(X509Certificate2 cert)
        {
            if (cert == null) return "无";
            var oids = new List<string>();
            var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (eku != null)
            {
                foreach (var usage in eku.EnhancedKeyUsages)
                {
                    if (usage.Value.StartsWith("1.3.6.1.4.1.60896"))
                        oids.Add(GetFriendlyName(usage.Value));
                }
            }
            return oids.Count > 0 ? string.Join(", ", oids) : "无权限";
        }

        private static bool HasOid(X509Certificate2 cert, string oidValue)
        {
            var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (eku == null) return false;
            return eku.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == oidValue);
        }

        // --- 权限检查逻辑 (库内部使用) ---
        public static bool HasFullAccess(X509Certificate2 cert) => HasOid(cert, FullAccess);

        public static bool CanEncrypt(X509Certificate2 cert)
        {
            if (HasFullAccess(cert)) return true;
            return HasOid(cert, Encrypt) && HasOid(cert, Sign);
        }

        public static bool CanVerify(X509Certificate2 cert)
        {
            if (HasFullAccess(cert)) return true;
            return HasOid(cert, Verify);
        }

        public static bool CanDecrypt(X509Certificate2 cert)
        {
            if (HasFullAccess(cert)) return true;
            return HasOid(cert, Decrypt) && HasOid(cert, Verify);
        }
    }
}
