using System;

namespace FceCore
{
    /// <summary>
    /// FCE 操作通用的异常基类
    /// </summary>
    public class FceException : Exception
    {
        public FceException(string message) : base(message) { }
        public FceException(string message, Exception innerException) : base(message, innerException) { }
    }

    /// <summary>
    /// 当证书权限不足以执行该操作时抛出
    /// </summary>
    public class FcePermissionException : FceException
    {
        public string RequiredPermission { get; }
        public string ActualPermission { get; }

        public FcePermissionException(string message, string required, string actual)
            : base(message)
        {
            RequiredPermission = required;
            ActualPermission = actual;
        }
    }

    /// <summary>
    /// 当 FCE 文件格式无效、损坏或被篡改时抛出
    /// </summary>
    public class FceFileFormatException : FceException
    {
        public FceFileFormatException(string message) : base(message) { }
        public FceFileFormatException(string message, Exception innerException) : base(message, innerException) { }
    }

    /// <summary>
    /// 当签名验证失败或解密过程出错时抛出
    /// </summary>
    public class FceCryptographicException : FceException
    {
        public FceCryptographicException(string message) : base(message) { }
        public FceCryptographicException(string message, Exception innerException) : base(message, innerException) { }
    }
}
