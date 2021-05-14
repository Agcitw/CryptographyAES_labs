using CryptographyLabs;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UnitTests
{
    public class Lab1TasksTest
    {
        [Test]
        public void TestTask11()
        {
            uint value = 0b1000_1111_0110_0101_1010_1101;
            int[] indices = new int[]
            {
                0, 1, 4, 7, 24
            };
            byte[] expected = new byte[]
            {
                1, 0, 0, 1, 0
            };

            for (int i = 0; i < indices.Length; ++i)
            {
                Assert.AreEqual(expected[i], Bitops.GetKthBit(value, indices[i]));
            }
        }

        [Test]
        public void TestTask12()
        {
            uint value = 0b1100_1001;

            Assert.AreEqual(0b1110_1001u, Bitops.SwitchKthBit(value, 5, true));
            Assert.AreEqual(0b1100_1001u, Bitops.SwitchKthBit(value, 0, true));
            Assert.AreEqual(0b1100_1000u, Bitops.SwitchKthBit(value, 0, false));
            Assert.AreEqual(0b0100_1001u, Bitops.SwitchKthBit(value, 7, false));
        }

        [Test]
        public void TestTask13()
        {
            uint value = 0b1100_1001;

            Assert.AreEqual(0b1100_1010u, Bitops.SwapBits(value, 0, 1), "0");
            Assert.AreEqual(0b1100_1001u, Bitops.SwapBits(value, 1, 2));
            Assert.AreEqual(0b1110_1000u, Bitops.SwapBits(value, 0, 5));
            Assert.AreEqual(0b1110_1000u, Bitops.SwapBits(value, 5, 0));
            Assert.AreEqual(0b1100_1001u, Bitops.SwapBits(value, 0, 7));
        }

        [Test]
        public void TestTask14()
        {
            uint[] values = new uint[]
            {
                0b1000,
                0b1111,
                0b1010_1110
            };
            int[] m = new int[]
            {
                4,
                2,
                7
            };
            uint[] expected = new uint[]
            {
                0,
                0b1100,
                0b1000_0000
            };

            for (int i = 0; i < values.Length; ++i)
            {
                Assert.AreEqual(expected[i], Bitops.NullifyMLowBits(values[i], m[i]));
            }
        }

        [Test]
        public void TestTask21()
        {
            uint[] value = new uint[]
            {
                0b1101_0010,
                0b1101_0010,
                0b1010_0011
            };
            int[] len = new int[]
            {
                8,
                8,
                8
            };
            int[] i = new int[]
            {
                2,
                7,
                3
            };
            uint[] expected = new uint[]
            {
                0b1110,
                0b11_0100_1101_0010,
                0b10_1011
            };

            for (int j = 0; j < value.Length; ++j)
            {
                Assert.AreEqual(expected[j], Bitops.ConcatExtremeBits(value[j], len[j], i[j]));
            }
        }

        [Test]
        public void TestTask22()
        {
            uint[] value = new uint[]
            {
                0b1101_0010,
                0b1101_0010,
                0b1010_0011,
                0b1101,
                0b1001_1101_0011_1111
            };
            int[] len = new int[]
            {
                8,
                8,
                8,
                8,
                16
            };
            int[] i = new int[]
            {
                2,
                4,
                3,
                0,
                2
            };
            uint[] expected = new uint[]
            {
                0b0100,
                0,
                0,
                0b1101,
                0b0111_0100_1111
            };

            for (int j = 0; j < value.Length; ++j)
            {
                Assert.AreEqual(expected[j], Bitops.GetCentralBits(value[j], len[j], i[j]), $"test #{j}");
            }

        }

        [Test]
        public void TestTask3()
        {
            uint value = 0b11001010_10001000_11101111_11110000;
            byte[][] indices = new byte[][]
            {
                new byte[] { 0, 2, 1, 3 },
                new byte[] { 3, 2, 1, 0 },
                new byte[] { 0, 0, 0, 1 },
                new byte[] { 0, 1, 2, 3 }
            };
            uint[] expected = new uint[]
            {
                0b11110000_10001000_11101111_11001010,
                0b11001010_10001000_11101111_11110000,
                0b11110000_11110000_11110000_11101111,
                0b11110000_11101111_10001000_11001010
            };

            for (int i = 0; i < indices.Length; ++i)
            {
                Assert.AreEqual(expected[i], Bitops.BytePermutation(value, indices[i]), $"test #{i}");
            }
        }

        [Test]
        public void TestTask4()
        {
            uint[] a = new uint[]
            {
                0b11111,
                0b10100,
                0b10000000_00000000_00000000_00000000,
                0b101010100
            };
            uint[] expected = new uint[]
            {
                1,
                0b100,
                0b10000000_00000000_00000000_00000000,
                0b100
            };

            for (int i = 0; i < a.Length; ++i)
            {
                Assert.AreEqual(expected[i], Bitops.Task4(a[i]));
            }

        }

        [Test]
        public void TestTask5()
        {
            uint[] x = new uint[]
            {
                0b1001_1101,
                0b100,
                0b1,
                0b11110000_11111111
            };
            int[] expected = new int[]
            {
                7,
                2,
                0,
                15
            };

            for (int i = 0; i < x.Length; ++i)
            {
                Assert.AreEqual(expected[i], Bitops.Task5(x[i]));
            }

        }

        [Test]
        public void TestTask6()
        {
            uint[] a = new uint[]
            {
                0b1101_0100,
                0b11001010_10001000_11101111_11110000,
                0b1,
                0b10101000_11010100,
                0b1,
                0b1010101
            };
            byte[] p = new byte[]
            {
                3,
                5,
                0,
                3,
                1,
                0
            };
            byte[] expected = new byte[]
            {
                0,
                1,
                1,
                0,
                1,
                1
            };

            for (int i = 0; i < a.Length; ++i)
            {
                Assert.AreEqual(expected[i], Bitops.XorBits(a[i], p[i]));
            }

        }

        [Test]
        public void TestTask7Left()
        {
            uint[] a = new uint[]
            {
                0b11011,
                0b11011,
                0b11011001,
                0b1101
            };
            byte[] len = new byte[]
            {
                5,
                5,
                4,
                4
            };
            byte[] n = new byte[]
            {
                1,
                0,
                2,
                6
            };
            uint[] expected = new uint[]
            {
                0b10111,
                0b11011,
                0b0110,
                0b0111
            };

            for (int i = 0; i < a.Length; ++i)
            {
                Assert.AreEqual(expected[i], Bitops.CycleShiftLeft(a[i], len[i], n[i]), $"test #{i}");
            }
        }

        [Test]
        public void TestTask7Right()
        {
            uint[] a = new uint[]
            {
                0b11011,
                0b11011,
                0b11011001,
                0b1101
            };
            byte[] len = new byte[]
            {
                5,
                5,
                4,
                4
            };
            byte[] n = new byte[]
            {
                1,
                0,
                1,
                6
            };
            uint[] expected = new uint[]
            {
                0b11101,
                0b11011,
                0b1100,
                0b0111
            };

            for (int i = 0; i < a.Length; ++i)
            {
                Assert.AreEqual(expected[i], Bitops.CycleShiftRight(a[i], len[i], n[i]), $"test #{i}");
            }
        }

        [Test]
        public void TestTask8()
        {
            uint[] a = new uint[]
            {
                0b10101110,
                0b1011,
                0b11010100
            };
            byte[] n = new byte[]
            {
                8,
                4,
                8
            };
            byte[][] transposition = new byte[][]
            {
                new byte[] {5, 3, 7, 1, 4, 0, 6, 2},
                new byte[] {0, 2},
                new byte[] {2, 0, 0, 7, 4}
            };
            uint[] expected = new uint[]
            {
                0b11110001,
                0b10,
                0b10011
            };

            for (int i = 0; i < a.Length; ++i)
            {
                Assert.AreEqual(expected[i], Bitops.BitPermutation(a[i], transposition[i]));
            }


        }
    }
}
