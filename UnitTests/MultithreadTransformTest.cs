using CryptographyLabs.Crypto;
using CryptographyLabs.Crypto.BlockCouplingModes;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace UnitTests
{
    
    public class MultithreadTransformTest
    {
        private INiceCryptoTransform _encryptor;
        private INiceCryptoTransform _decryptor;
        private byte[][] _texts;

        [SetUp]
        public void Init()
        {
            Random random = new Random(126);
            byte[] tmKey = new byte[8];
            random.NextBytes(tmKey);
            ulong key56 = BitConverter.ToUInt64(tmKey);

            _encryptor = DES_.GetNice(key56, CryptoDirection.Encrypt);
            _decryptor = DES_.GetNice(key56, CryptoDirection.Decrypt);

            _texts = new byte[3][];
            _texts[0] = new byte[800_003];
            _texts[1] = new byte[800_000];
            _texts[2] = new byte[5];
            for (int i = 0; i < _texts.Length; i++)
            {
                random.NextBytes(_texts[i]);
            }
        }

        [Test]
        public async Task Test0()
        {
            await Check(_texts[0]);
        }

        [Test]
        public async Task Test1()
        {
            await Check(_texts[1]);
        }

        [Test]
        public async Task Test2()
        {
            await Check(_texts[2]);
        }

        private async Task Check(byte[] text)
        {
            byte[] encrypted = await ECB.TransformAsync(text, _encryptor);
            byte[] decrypted = await ECB.TransformAsync(encrypted, _decryptor);

            Assert.AreEqual(text.Length, decrypted.Length);
            for (int i = 0; i < text.Length; i++)
            {
                Assert.AreEqual(text[i], decrypted[i], $"i={i}, Text length: {text.Length}");
            }
        }
    }
}
