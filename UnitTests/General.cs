using CryptographyLabs.Crypto;
using CryptographyLabs.Crypto.BlockCouplingModes;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace UnitTests
{
    static class General
    {
        public static readonly byte[] EmptyText = Array.Empty<byte>();
        public static readonly byte[] ShortText0;
        public static readonly byte[] LongText1;

        static General()
        {
            Random random = new Random(992);

            ShortText0 = new byte[8];
            random.NextBytes(ShortText0);

            LongText1 = new byte[800_001];
            random.NextBytes(LongText1);
        }

        public static async Task CheckMultithread(Func<INiceCryptoTransform> getEncryptor, 
            Func<INiceCryptoTransform> getDecryptor)
        {
            await CheckMultithread(ShortText0, getEncryptor, getDecryptor);
            await CheckMultithread(LongText1, getEncryptor, getDecryptor);
        }

        private static async Task CheckMultithread(byte[] text, Func<INiceCryptoTransform> getEncryptor,
            Func<INiceCryptoTransform> getDecryptor)
        {
            byte[] encrypted = await ECB.TransformAsync(text, getEncryptor());
            byte[] decrypted = await ECB.TransformAsync(encrypted, getDecryptor());

            Assert.AreEqual(text.Length, decrypted.Length);
            for (int i = 0; i < text.Length; i++)
                Assert.AreEqual(text[i], decrypted[i]);
        }

        public static void Check(Func<ICryptoTransform> getEncryptor, Func<ICryptoTransform> getDecryptor, int bytesCount)
        {
            Random random = new Random(339);
            byte[] text = new byte[bytesCount];
            random.NextBytes(text);
            Check(text, getEncryptor, getDecryptor);
        }

        public static void Check(Func<ICryptoTransform> getEncryptor, Func<ICryptoTransform> getDecryptor)
        {
            Check(EmptyText, getEncryptor, getDecryptor);
            Check(ShortText0, getEncryptor, getDecryptor);
            Check(LongText1, getEncryptor, getDecryptor);
        }

        private static void Check(byte[] text, Func<ICryptoTransform> getEncryptor, Func<ICryptoTransform> getDecryptor)
        {
            byte[] encrypted = Transform(text, getEncryptor());
            byte[] decrypted = Transform(encrypted, getDecryptor());

            Assert.AreEqual(text.Length, decrypted.Length);
            for (int i = 0; i < text.Length; ++i)
                Assert.AreEqual(text[i], decrypted[i]);
        }

        private static byte[] Transform(byte[] text, ICryptoTransform transform)
        {
            using (MemoryStream outStream = new MemoryStream())
            {
                using (MemoryStream inStream = new MemoryStream(text))
                using (CryptoStream crStream = new CryptoStream(inStream, transform, CryptoStreamMode.Read))
                {
                    crStream.CopyTo(outStream);
                }
                return outStream.ToArray();
            }
        }

    }
}
