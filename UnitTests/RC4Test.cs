using CryptographyLabs.Crypto;
using NUnit.Framework;
using System;

namespace UnitTests
{
    public class RC4Test
    {
        [Test]
        public void Test()
        {
            Random random = new Random(123);
            int byteSize = 800000;
            byte[] text = new byte[byteSize];
            random.NextBytes(text);
            for (int i = 0; i < 10; ++i)
            {
                byte[] key = new byte[8 * i + 8];
                random.NextBytes(key);

                var encrTrans = RC4.Get(key);
                var decrTrans = RC4.Get(key);

                byte[] encr = new byte[byteSize];
                encrTrans.TransformBlock(text, 0, byteSize, encr, 0);
                byte[] decr = new byte[byteSize];
                decrTrans.TransformBlock(encr, 0, byteSize, decr, 0);

                for (int j = 0; j < byteSize; ++j)
                    Assert.AreEqual(text[j], decr[j], $"{j}");
            }

        }

    }
}
