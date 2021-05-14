using CryptographyLabs.Crypto;
using NUnit.Framework;
using System;
using System.Security.Cryptography;

namespace UnitTests
{
    public class RijndaelTest
    {
        // 16 24 32
        private byte[][] _keys = new byte[3][];
        private byte[][] _iv = new byte[3][];

        [SetUp]
        public void SetUp()
        {
            Random random = new Random(129);
            for (int i = 0; i < 3; i++)
            {
                _keys[i] = new byte[16 + i * 8];
                _iv[i] = new byte[16 + i * 8];
                random.NextBytes(_keys[i]);
                random.NextBytes(_iv[i]);
            }
        }

        [Test]
        public void Test1_ECB()
        {
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    Func<ICryptoTransform> getEncryptor = () => Rijndael_.Get(_keys[i], (Rijndael_.Size)j, 
                         CryptoDirection.Encrypt);
                    Func<ICryptoTransform> getDecryptor = () => Rijndael_.Get(_keys[i], (Rijndael_.Size)j, 
                         CryptoDirection.Decrypt);

                    General.Check(getEncryptor, getDecryptor, 10_001);
                    General.Check(getEncryptor, getDecryptor, 0);
                    General.Check(getEncryptor, getDecryptor, 7);
                }
            }
        }

        [Test]
        public void Test2_CBC()
        {
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    Func<ICryptoTransform> getEncryptor = () => Rijndael_.Get(_keys[i], (Rijndael_.Size)j, 
                        _iv[j], Rijndael_.Mode.CBC, CryptoDirection.Encrypt);
                    Func<ICryptoTransform> getDecryptor = () => Rijndael_.Get(_keys[i], (Rijndael_.Size)j,
                        _iv[j], Rijndael_.Mode.CBC, CryptoDirection.Decrypt);

                    General.Check(getEncryptor, getDecryptor, 10_001);
                    General.Check(getEncryptor, getDecryptor, 0);
                    General.Check(getEncryptor, getDecryptor, 7);
                }
            }
        }

        [Test]
        public void Test3_CFB()
        {
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    Func<ICryptoTransform> getEncryptor = () => Rijndael_.Get(_keys[i], (Rijndael_.Size)j, 
                        _iv[j], Rijndael_.Mode.CFB, CryptoDirection.Encrypt);
                    Func<ICryptoTransform> getDecryptor = () => Rijndael_.Get(_keys[i], (Rijndael_.Size)j,
                        _iv[j], Rijndael_.Mode.CFB, CryptoDirection.Decrypt);

                    General.Check(getEncryptor, getDecryptor, 10_001);
                    General.Check(getEncryptor, getDecryptor, 0);
                    General.Check(getEncryptor, getDecryptor, 7);
                }
            }
        }

        [Test]
        public void Test4_OFB()
        {
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    Func<ICryptoTransform> getEncryptor = () => Rijndael_.Get(_keys[i], (Rijndael_.Size)j,
                        _iv[j], Rijndael_.Mode.OFB, CryptoDirection.Encrypt);
                    Func<ICryptoTransform> getDecryptor = () => Rijndael_.Get(_keys[i], (Rijndael_.Size)j,
                        _iv[j], Rijndael_.Mode.OFB, CryptoDirection.Decrypt);

                    General.Check(getEncryptor, getDecryptor, 10_001);
                    General.Check(getEncryptor, getDecryptor, 0);
                    General.Check(getEncryptor, getDecryptor, 7);
                }
            }
        }
    }
}
