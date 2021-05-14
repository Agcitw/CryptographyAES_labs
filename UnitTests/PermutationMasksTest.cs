using ConsoleTests;
using CryptographyLabs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using CryptographyLabs.Crypto;
using NUnit.Framework;

namespace UnitTests
{
    public class PermutationMasksTest
    {
        [Test]
        public void Test0_PermutationNetwork()
        {
            byte[] _IPTranspose = new byte[]
            {
                57, 49, 41, 33, 25, 17, 9, 1,   59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7,
                56, 48, 40, 32, 24, 16, 8, 0,   58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,  62, 54, 46, 38, 30, 22, 14, 6
            };
            byte[] _IPTransposeReversed = new byte[64];
            for (int i = 0; i < 64; ++i)
                _IPTransposeReversed[i] = _IPTranspose[63 - i];
            byte[] _IPTransposeInversed = new byte[64];
            for (int i = 0; i < 64; ++i)
                _IPTransposeInversed[_IPTranspose[i]] = (byte)i;
            byte[] _IPTransposeInversedReversed = new byte[64];
            for (int i = 0; i < 64; ++i)
                _IPTransposeInversedReversed[_IPTranspose[63 - i]] = (byte)i;
            var network = new PermutationNetwork(_IPTransposeInversedReversed);


            Random random = new Random(123);
            byte[] buf = new byte[8];
            for (int i = 0; i < 10000; ++i)
            {
                random.NextBytes(buf);
                ulong value = BitConverter.ToUInt64(buf, 0);
                ulong expected = Bitops.BitPermutation(value, _IPTranspose);

                ulong actual = network.Permute(value);

                Assert.AreEqual(expected, actual);
            }



        }

        [Test]
        public void Test1_IPPermutation()
        {
            byte[] IPPermutation = new byte[64]
            {
                57, 49, 41, 33, 25, 17, 9, 1,   59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7,
                56, 48, 40, 32, 24, 16, 8, 0,   58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,  62, 54, 46, 38, 30, 22, 14, 6
            };
            ulong[] masks = (ulong[])typeof(DES_).GetField("_IPPermMasks",
                BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);

            Random random = new Random(123);
            byte[] buf = new byte[8];
            for (int i = 0; i < 1000; ++i)
            {
                random.NextBytes(buf);
                ulong value = BitConverter.ToUInt64(buf, 0);

                ulong expected = Bitops.BitPermutation(value, IPPermutation);
                ulong actual = Bitops.SwapBitsMasks64(value, masks);
                Assert.AreEqual(expected, actual);
            }
        }

        [Test]
        public void Test2_IPInvPermutation()
        {
            byte[] IPInvPermutation = new byte[64]
            {
                39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24
            };
            ulong[] masks = (ulong[])typeof(DES_).GetField("_IPInvPermMasks",
                BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);

            Random random = new Random(123);
            byte[] buf = new byte[8];
            for (int i = 0; i < 1000; ++i)
            {
                random.NextBytes(buf);
                ulong value = BitConverter.ToUInt64(buf, 0);

                ulong expected = Bitops.BitPermutation(value, IPInvPermutation);
                ulong actual = Bitops.SwapBitsMasks64(value, masks);
                Assert.AreEqual(expected, actual);
            }
        }

        [Test]
        public void Test3_C0Permutation()
        {
            byte[] C0Permutation = new byte[28]
            {
                56, 48, 40, 32, 24, 16,8, 0, 57, 49, 41, 33, 25, 17,
                9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35
            };
            //Type DESCrTransType = typeof(DES).GetNestedType("DESCryptoTransform", BindingFlags.NonPublic);
            //ulong[] masks = (ulong[])DESCrTransType.GetField("_C0PermMasks", BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);
            ulong[] masks = (ulong[])typeof(DES_).GetField("_C0PermMasks",
                BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);

            Random random = new Random(123);
            byte[] buf = new byte[8];
            for (int i = 0; i < 1000; ++i)
            {
                random.NextBytes(buf);
                ulong value = BitConverter.ToUInt64(buf, 0);

                ulong expected = Bitops.BitPermutation(value, C0Permutation);
                ulong actual = Bitops.SwapBitsMasks64(value, masks) & 0xf_ff_ff_ff;
                Assert.AreEqual(expected, actual);
            }
        }

        [Test]
        public void Test4_D0Permutation()
        {
            byte[] D0Permutation = new byte[28]
            {
                62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
                13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3
            };
            //Type DESCrTransType = typeof(DES).GetNestedType("DESCryptoTransform", BindingFlags.NonPublic);
            //ulong[] masks = (ulong[])DESCrTransType.GetField("_D0PermMasks", BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);
            ulong[] masks = (ulong[])typeof(DES_).GetField("_D0PermMasks",
                BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);

            Random random = new Random(123);
            byte[] buf = new byte[8];
            for (int i = 0; i < 1000; ++i)
            {
                random.NextBytes(buf);
                ulong value = BitConverter.ToUInt64(buf, 0);

                ulong expected = Bitops.BitPermutation(value, D0Permutation);
                ulong actual = Bitops.SwapBitsMasks64(value, masks) & 0xf_ff_ff_ff;
                Assert.AreEqual(expected, actual);
            }
        }

        [Test]
        public void Test5_KeyFinalPermutation()
        {
            byte[] keyFinalPermutation = new byte[48]
            {
                13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
                25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39,
                50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
            };
            //Type DESCrTransType = typeof(DES).GetNestedType("DESCryptoTransform", BindingFlags.NonPublic);
            //ulong[] masks = (ulong[])DESCrTransType.GetField("_keyFinalPermMasks", BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);
            ulong[] masks = (ulong[])typeof(DES_).GetField("_keyFinalPermMasks",
                BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);

            Random random = new Random(123);
            byte[] buf = new byte[8];
            for (int i = 0; i < 1000; ++i)
            {
                random.NextBytes(buf);
                ulong value = BitConverter.ToUInt64(buf, 0);

                ulong expected = Bitops.BitPermutation(value, keyFinalPermutation);
                ulong actual = Bitops.SwapBitsMasks64(value, masks) & 0xff_ff_ff_ff_ff_ff;
                Assert.AreEqual(expected, actual);
            }
        }

        [Test]
        public void Test6_PPermutation()
        {
            byte[] PPermutation = new byte[32]
            {
                15, 6, 19, 20, 28, 11, 27, 16,
                0, 14, 22, 25, 4, 17, 30, 9,
                1, 7, 23, 13, 31, 26, 2, 8,
                18, 12, 29, 5, 21, 10, 3, 24
            };
            //Type DESCrTransType = typeof(DES).GetNestedType("DESCryptoTransform", BindingFlags.NonPublic);
            //ulong[] masks = (ulong[])DESCrTransType.GetField("_PPermMasks", BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);
            ulong[] masks = (ulong[])typeof(DES_).GetField("_PPermMasks",
                BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);

            Random random = new Random(123);
            byte[] buf = new byte[8];
            for (int i = 0; i < 1000; ++i)
            {
                random.NextBytes(buf);
                ulong value = BitConverter.ToUInt64(buf, 0);

                ulong expected = Bitops.BitPermutation(value, PPermutation);
                ulong actual = Bitops.SwapBitsMasks64(value, masks) & 0xff_ff_ff_ff;
                Assert.AreEqual(expected, actual);
            }
        }
    }
}
