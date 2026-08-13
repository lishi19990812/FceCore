using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FceCore
{
    internal static class FceFileFormat
    {
        private static readonly byte[] MagicHead = Encoding.ASCII.GetBytes("FCEFILE1");
        private static readonly byte[] MagicTail = Encoding.ASCII.GetBytes("ENDFCE1!");

        // 包装数据：[Head][Type][MD5][Payload][Tail]
        public static byte[] Wrap(byte[] payload, int type)
        {
            using var md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(payload);

            using var ms = new MemoryStream();
            ms.Write(MagicHead, 0, 8);
            ms.WriteByte((byte)type);
            ms.Write(hash, 0, 16);
            ms.Write(payload, 0, payload.Length);
            ms.Write(MagicTail, 0, 8);
            return ms.ToArray();
        }

        // 解包数据
        public static byte[] Unwrap(byte[] fileData)
        {
            if (fileData.Length < 8 + 1 + 16 + 8)
                throw new InvalidDataException("文件格式无效：长度不足。");

            // 校验头尾
            byte[] head = new byte[8];
            Array.Copy(fileData, 0, head, 0, 8);
            byte[] tail = new byte[8];
            Array.Copy(fileData, fileData.Length - 8, tail, 0, 8);

            if (!head.SequenceEqual(MagicHead) || !tail.SequenceEqual(MagicTail))
                throw new InvalidDataException("文件标识符损坏，非有效的FCE文件。");

            // 提取数据
            int payloadLen = fileData.Length - 8 - 1 - 16 - 8;
            byte[] payload = new byte[payloadLen];
            Array.Copy(fileData, 25, payload, 0, payloadLen);

            // 校验 MD5
            byte[] storedHash = new byte[16];
            Array.Copy(fileData, 9, storedHash, 0, 16);

            using var md5 = MD5.Create();
            byte[] actualHash = md5.ComputeHash(payload);

            if (!actualHash.SequenceEqual(storedHash))
                throw new CryptographicException("文件校验失败！数据已损坏或被篡改。");

            return payload;
        }
    }
}
