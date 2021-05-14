using CryptographyLabs.Crypto;
using NUnit.Framework;
using System;
using System.Security.Cryptography;

namespace UnitTests
{
    public class DESTest
    {
        private ulong _key;
        private byte[] _iv = new byte[DES_.BlockSize];

        [SetUp]
        public void SetUp()
        {
            Random random = new Random(992);
            
            byte[] keyTm = new byte[8];
            random.NextBytes(keyTm);
            _key = BitConverter.ToUInt64(keyTm, 0);

            random.NextBytes(_iv);
        }

        [Test]
        public void Test1_DESCryptoTransform()
        {
            Func<ICryptoTransform> getEncryptor = () => DES_.Get(_key, CryptoDirection.Encrypt);
            Func<ICryptoTransform> getDecryptor = () => DES_.Get(_key, CryptoDirection.Decrypt);

            General.Check(getEncryptor, getDecryptor);
        }

        [Test]
        public void Test2_CBC()
        {
            Func<ICryptoTransform> getEncryptor = () => DES_.Get(_key, _iv, DES_.Mode.CBC, CryptoDirection.Encrypt);
            Func<ICryptoTransform> getDecryptor = () => DES_.Get(_key, _iv, DES_.Mode.CBC, CryptoDirection.Decrypt);

            General.Check(getEncryptor, getDecryptor);
        }

        [Test]
        public void Test3_CFB()
        {
            Func<ICryptoTransform> getEncryptor = () => DES_.Get(_key, _iv, DES_.Mode.CFB, CryptoDirection.Encrypt);
            Func<ICryptoTransform> getDecryptor = () => DES_.Get(_key, _iv, DES_.Mode.CFB, CryptoDirection.Decrypt);

            General.Check(getEncryptor, getDecryptor);
        }

        [Test]
        public void Test4_OFB()
        {
            Func<ICryptoTransform> getEncryptor = () => DES_.Get(_key, _iv, DES_.Mode.OFB, CryptoDirection.Encrypt);
            Func<ICryptoTransform> getDecryptor = () => DES_.Get(_key, _iv, DES_.Mode.OFB, CryptoDirection.Decrypt);

            General.Check(getEncryptor, getDecryptor);
        }


    }
}
