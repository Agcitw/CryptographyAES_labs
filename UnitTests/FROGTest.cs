using CryptographyLabs.Crypto;
using CryptographyLabs.Crypto.BlockCouplingModes;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace UnitTests
{
    public class FROGTest
    {
        private byte[] _key;
        private byte[] _iv;
        private FROGProvider _provider;

        [SetUp]
        public void SetUp()
        {
            Random random = new Random(144);
            _key = new byte[25];
            random.NextBytes(_key);

            _iv = new byte[FROGProvider.BlockSize];
            random.NextBytes(_iv);

            _provider = new FROGProvider(_key);
        }

        [Test]
        public async Task Test0_ECBMultithread()
        {
            Func<INiceCryptoTransform> getEncryptor = () => _provider.CreateNice(CryptoDirection.Encrypt);
            Func<INiceCryptoTransform> getDecryptor = () => _provider.CreateNice(CryptoDirection.Decrypt);

            await General.CheckMultithread(getEncryptor, getDecryptor);
        }

        [Test]
        public void Test1_ECB()
        {
            Func<ICryptoTransform> getEncryptor = () => _provider.Create(CryptoDirection.Encrypt);
            Func<ICryptoTransform> getDecryptor = () => _provider.Create(CryptoDirection.Decrypt);
            
            General.Check(getEncryptor, getDecryptor);
        }

        [Test]
        public void Test2_CBC()
        {
            Func<ICryptoTransform> getEncryptor = 
                () => _provider.Create(CryptoDirection.Encrypt, FROGProvider.Mode.CBC, _iv);
            Func<ICryptoTransform> getDecryptor = 
                () => _provider.Create(CryptoDirection.Decrypt, FROGProvider.Mode.CBC, _iv);

            General.Check(getEncryptor, getDecryptor);
        }

        [Test]
        public void Test3_CFB()
        {
            Func<ICryptoTransform> getEncryptor = 
                () => _provider.Create(CryptoDirection.Encrypt, FROGProvider.Mode.CFB, _iv);
            Func<ICryptoTransform> getDecryptor = 
                () => _provider.Create(CryptoDirection.Decrypt, FROGProvider.Mode.CFB, _iv);

            General.Check(getEncryptor, getDecryptor);
        }

        [Test]
        public void Test4_OFB()
        {
            Func<ICryptoTransform> getEncryptor = 
                () => _provider.Create(CryptoDirection.Encrypt, FROGProvider.Mode.OFB, _iv);
            Func<ICryptoTransform> getDecryptor = 
                () => _provider.Create(CryptoDirection.Decrypt, FROGProvider.Mode.OFB, _iv);

            General.Check(getEncryptor, getDecryptor);
        }

    }
}
