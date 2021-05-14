using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Reflection;
using System.Globalization;
using System.Threading;
using System.Numerics;
using CryptographyLabs;
using System.Collections;
using CryptographyLabs.Crypto;
using CryptographyLabs.Extensions;
using CryptographyLabs.Crypto.IO;
using CryptographyLabs.Crypto.BlockCouplingModes;

namespace ConsoleTests
{

    public class RSACryptoTransform : ICryptoTransform
    {
        private int _inputBlockSize;
        public int InputBlockSize => _inputBlockSize;

        private int _outputBlockSize;
        public int OutputBlockSize => _outputBlockSize;

        public bool CanTransformMultipleBlocks => true;

        public bool CanReuseTransform => false;

        private BigInteger _n, _e, _d;
        private byte[] _inputBuf;


        public RSACryptoTransform()
        {
            Random random = new Random(123);// TODOL seed
            BigInteger p = Program.RandomPrime(128, 5, random);
            BigInteger q = Program.RandomPrime(128, 5, random);
            _n = p * q;
            BigInteger phi_n = (p - 1) * (q - 1);
            if (!TryFindExponents(phi_n, out _e, out _d))
                throw new Exception(); // TODOL regenerate p, q
            

            _inputBlockSize = Math.Min(p.BytesCount(), q.BytesCount()) - 1;
            _outputBlockSize = _n.BytesCount();

            _inputBuf = new byte[_inputBlockSize + 1];
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            for (int i = 0; i < inputCount; ++i)
            {
                // TODOL to another func   transform_simple_block
                Array.Copy(inputBuffer, inputOffset + i * _inputBlockSize, _inputBuf, 0, _inputBlockSize);
                BigInteger text = new BigInteger(_inputBuf);
                BigInteger transformed = RSAAlg.BinPowMod(text, _e, _n);
                byte[] bytes = transformed.ToByteArrayWithoutZero();
                Array.Copy(bytes, 0, outputBuffer, outputOffset + i * _outputBlockSize, bytes.Length);
                for (int j = bytes.Length; j < _outputBlockSize; ++j)
                    outputBuffer[outputOffset + i * _outputBlockSize + j] = 0;
            }
            return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            throw new NotImplementedException();
        }

        // static
        private static bool TryFindExponents(BigInteger eulerFuncN, out BigInteger e, out BigInteger d)
        {
            List<int> primes = RSAAlg.CalcPrimes(100);
            Random random = new Random(123); // TODOL remove seed
            e = primes[random.Next(2, primes.Count)];
            if (RSAAlg.GCD(e, eulerFuncN, out d, out BigInteger _) == 1)
            {
                if (d < 0)
                    d = (d % eulerFuncN) + eulerFuncN;
                return true;
            }
            else
                return false;
        }
    }

    class Program
    {
        private static string pFilename = "p";
        private static string qFilename = "q";
        private static Random _random = new Random(123);

        static void Main(string[] args)
        {
            

            Console.WriteLine();
            Console.WriteLine("Press...");
            Console.ReadKey();
        }

        private static void Shaffle(byte[] arr)
        {
            for (int i = 0; i < arr.Length; i++)
            {
                int swapIndex = _random.Next(0, arr.Length);
                byte tm = arr[swapIndex];
                arr[swapIndex] = arr[i];
                arr[i] = tm;
            }
        }

        private static void NiceStreamTest()
        {
            Random random = new Random(1241);
            byte[] text = new byte[100_001];
            random.NextBytes(text);
            Console.WriteLine(text.Length);

            byte[] keyTm = new byte[8];
            random.NextBytes(keyTm);
            ulong key = BitConverter.ToUInt64(keyTm);

            INiceCryptoTransform encryptor = DES_.GetNice(key, CryptoDirection.Encrypt);
            Console.WriteLine(encryptor.InputBlockSize);

            byte[] encrypted;
            using (MemoryStream outStream = new MemoryStream())
            {
                using (NiceCryptoWriteStream s = new NiceCryptoWriteStream(outStream, encryptor))
                using (MemoryStream inStream = new MemoryStream(text))
                {
                    inStream.CopyTo(s);
                }
                encrypted = outStream.ToArray();
            }

            Console.WriteLine(encrypted.Length);


            INiceCryptoTransform decryptor = DES_.GetNice(key, CryptoDirection.Decrypt);

            byte[] decrypted;
            using (MemoryStream outStream = new MemoryStream())
            {
                using (NiceCryptoWriteStream s = new NiceCryptoWriteStream(outStream, decryptor))
                using (MemoryStream inStream = new MemoryStream(encrypted))
                {
                    byte[] buf = new byte[7];
                    while (true)
                    {
                        int hasRead = inStream.Read(buf);
                        if (hasRead == 0)
                            break;
                        s.Write(buf, 0, hasRead);
                    }
                }
                decrypted = outStream.ToArray();
            }

            Console.WriteLine(decrypted.Length);

            if (decrypted.Length != text.Length)
                Console.WriteLine($"{decrypted.Length} != {text.Length}");
            else
            {
                for (int i = 0; i < text.Length; i++)
                {
                    if (text[i] != decrypted[i])
                        Console.WriteLine($"i={i}, text[i]={text[i]}, decrypted[i]={decrypted[i]}");
                }
            }
        }

        private static void FROGSpeedTest()
        {
            Random random = new Random(123);

            byte[] key = new byte[25];
            random.NextBytes(key);

            FROGProvider provider = new FROGProvider(key);
            using ICryptoTransform encryptor = provider.Create(CryptoDirection.Encrypt);
            using ICryptoTransform decryptor = provider.Create(CryptoDirection.Decrypt);

            int bytesCount = 10_000_000;
            byte[] text = new byte[10_000_000];
            random.NextBytes(text);

            DateTime start;
            using MemoryStream inStream = new MemoryStream(text);
            using MemoryStream outStream = new MemoryStream();
            using (CryptoStream crStream = new CryptoStream(inStream, encryptor, CryptoStreamMode.Read))
            {
                start = DateTime.Now;
                crStream.CopyTo(outStream);
            }
            byte[] encrypted = outStream.ToArray();
            TimeSpan doneIn = DateTime.Now - start;
            double speed = bytesCount / doneIn.TotalSeconds;
            Console.WriteLine($"{speed / 1024 / 1024} MB/s");
        }
        
        private static void PrintCycles(byte[] bytes)
        {
            Console.Write("Indices:    ");
            for (int i = 0; i < bytes.Length; i++)
            {
                if (i != 0)
                    Console.Write(", ");
                Console.Write(i.ToString().PadLeft(3, ' '));
            }
            Console.WriteLine();
            Console.Write("Full array: ");
            Print(bytes);

            BitArray used = new BitArray(bytes.Length, false);
            while (true)
            {
                int startIndex = used.FirstIndexOf(false);
                if (startIndex == -1)
                    break;
                byte index = (byte)startIndex;
                do
                {
                    Console.Write($"{index} -> ");
                    used[index] = true;
                    index = bytes[index];
                } while (index != startIndex);
                Console.WriteLine("begin");
            }
        }

        private static byte[][] MultiplyGFMtx(byte[][] mtx1, byte[][] mtx2)
        {
            byte[][] res = new byte[mtx1.Length][];
            for (int row = 0; row < mtx1.Length; row++)
            {
                res[row] = new byte[mtx1.Length];
                for (int col = 0; col < mtx1.Length; col++)
                {
                    byte tm = 0;
                    for (int i = 0; i < mtx1.Length; i++)
                    {
                        tm ^= GF.Multiply(mtx1[row][i], mtx2[i][col]);
                    }
                    res[row][col] = tm;
                }
            }
            return res;
        }

        private static byte[] MultiplyGFMtxVector(byte[][] mtx, byte[] vector)
        {
            byte[] res = new byte[mtx.Length];
            for (int row = 0; row < mtx.Length; row++)
            {
                res[row] = 0;
                for (int i = 0; i < mtx[row].Length; i++)
                    res[row] ^= GF.Multiply(mtx[row][i], vector[i]);
            }
            return res;
        }

        private static void PrintState(byte[] state)
        {
            int columnsCount = state.Length / 4;
            for (int row = 0; row < 4; row++)
            {
                Console.Write('\t');
                for (int col = 0; col < columnsCount; col++)
                {
                    if (col > 0)
                        Console.Write(", ");
                    Console.Write("0x");
                    Console.Write(Convert.ToString(state[row * columnsCount + col], 16).PadLeft(2, '0'));
                }
                Console.WriteLine();
            }
        }

        private static void Divide(ushort a, ushort b, out ushort div, out ushort mod)
        {
            int bDegree = DegreeOf(b);
            div = 0;
            mod = a;

            while (true)
            {
                int degree = DegreeOf(mod);
                if (degree < bDegree)
                    break;
                int shift = degree - bDegree;
                mod ^= (ushort)(b << shift);
                div |= (ushort)(1 << shift);
            }
        }

        private static int DegreeOf(ushort coefs)
        {
            int degree = 0;
            while (true)
            {
                coefs >>= 1;
                if (coefs == 0)
                    break;
                degree++;
            }
            return degree;
        }

        private static int DegreeOf(BigInteger coefs)
        {
            byte[] data = coefs.ToByteArrayWithoutZero();
            int degree = 0;
            while (true)
            {
                data[data.Length - 1] >>= 1;
                if (data[data.Length - 1] == 0)
                    break;
                degree++;
            }
            degree += 8 * (data.Length - 1);
            return degree;
        }

        private static void Print(byte[] bytes)
        {
            bool isFirst = true;
            foreach (var b in bytes)
            {
                if (isFirst)
                    isFirst = false;
                else
                    Console.Write(", ");
                Console.Write(b.ToString().PadLeft(3, ' '));
            }
            Console.WriteLine();
        }
        
        private static void Aga()
        {
            string errorsFilename = "errors.txt";

            Random random = new Random(DateTime.Now.Millisecond);

            LoadPrimesFromFiles(out BigInteger p, out BigInteger q);
            BigInteger n = p * q;
            BigInteger phi_n = (p - 1) * (q - 1);
            List<int> primes = RSAAlg.CalcPrimes(1000);
            BigInteger e, d;
            do
            {
                int index = random.Next(0, primes.Count);
                e = primes[index];
                primes.RemoveAt(index);
                Console.WriteLine("check for e");
            } while (RSAAlg.GCD(e, phi_n, out d, out BigInteger _) != 1);

            if (d < 0)
                d = (d % phi_n) + phi_n;


            int pBytesCount = BytesCount(p);
            int qBytesCount = BytesCount(q);
            int nBytesCount = BytesCount(n);
            int inputBlockSize = Math.Min(pBytesCount, qBytesCount) - 1;
            int outputBlockSize = nBytesCount;

            byte[] text = new byte[inputBlockSize + 1];
            byte[] encrypted = new byte[outputBlockSize + 1];
            byte[] decrypted = new byte[inputBlockSize + 1];
            for (int round = 0; ; ++round)
            {
                random.NextBytes(text);
                text[text.Length - 1] = 0;
                TransformBlock(text, encrypted, e, n);
                TransformBlock(encrypted, decrypted, d, n);

                bool isNice = true;
                for (int i = 0; i < text.Length; ++i)
                {
                    if (text[i] != decrypted[i])
                    {
                        isNice = false;
                        break;
                    }
                }
                
                if (!isNice)
                {
                    Console.WriteLine($"hueta {round}");
                    File.AppendAllLines(errorsFilename, new string[]
                    {
                        $"p = {p}",
                        $"q = {q}",
                        $"n = {n}",
                        $"e = {e}",
                        $"d = {d}",
                        $"text = {new BigInteger(text)}",
                        $"encrypted = {new BigInteger(encrypted)}",
                        $"decrypted = {new BigInteger(decrypted)}",
                        "---------------------------------------"
                    });
                }

                if (round % 100 == 0)
                {
                    Console.WriteLine($"{round} round done");
                }
            }

        }

        private static void TransformBlock(byte[] inputBlock, byte[] outputBlock,
            BigInteger exponent, BigInteger modulus)
        {
            BigInteger value = new BigInteger(inputBlock);
            BigInteger result = RSAAlg.BinPowMod(value, exponent, modulus);
            byte[] resultBytes = result.ToByteArray();
            if (resultBytes.Length <= outputBlock.Length)
            {
                Array.Copy(resultBytes, 0, outputBlock, 0, resultBytes.Length);
                for (int i = resultBytes.Length; i < outputBlock.Length; ++i)
                    outputBlock[i] = 0;
            }
            else
            {
                throw new Exception();// TODOL
            }
        }

        private static int BytesCount(BigInteger value)
        {
            byte[] bytes = value.ToByteArray();
            if (bytes.Length > 1 && bytes[bytes.Length - 1] == 0)
                return bytes.Length - 1;
            else
                return bytes.Length;
        }

        private static void GeneratePrimesInFiles()
        {
            int bytesCount = 128;
            Random random = new Random(123);
            BigInteger p = RandomPrime(bytesCount, 5, random);
            BigInteger q = RandomPrime(bytesCount, 5, random);

            File.WriteAllBytes(pFilename, p.ToByteArray());
            File.WriteAllBytes(qFilename, q.ToByteArray());
            Console.WriteLine("Generated");
            Console.WriteLine(p);
            Console.WriteLine();
            Console.WriteLine(q);
        }

        private static void LoadPrimesFromFiles(out BigInteger p, out BigInteger q)
        {
            byte[] bytes = File.ReadAllBytes(pFilename);
            p = new BigInteger(bytes);
            bytes = File.ReadAllBytes(qFilename);
            q = new BigInteger(bytes);
        }

        public static BigInteger RandomPrime(int bytesCount, int roundsCount, Random random)
        {
            byte[] bytes = new byte[bytesCount + 1];
            BigInteger result;
            do
            {
                random.NextBytes(bytes);
                bytes[bytes.Length - 1] = 0;
                result = new BigInteger(bytes);
            } while (!IsPrimeTest(result, roundsCount));

            return result;
        }

        // Тест Миллера-Рабина
        private static bool IsPrimeTest(BigInteger n, int roundsCount)
        {
            BigInteger nMinus1 = n - 1;
            Factor2Out(nMinus1, out int r, out BigInteger d);

            for (; roundsCount > 0; --roundsCount)
            {
                BigInteger a = RandomBigInteger(2, nMinus1);
                BigInteger x = RSAAlg.BinPowMod(a, d, n);
                if (x == 1 || x == nMinus1)
                    continue;

                bool flag = true;
                for (int i = 1; i < r; ++i)
                {
                    x = (x * x) % n;
                    if (x == nMinus1)
                    {
                        flag = false;
                        break;
                    }
                }

                if (flag)
                    return false;
            }

            return true;
        }

        private static void Factor2Out(BigInteger value, out int exponent2, out BigInteger remainder)
        {
            exponent2 = 0;
            remainder = value;
            while ((remainder & 1) == 0)
            {
                ++exponent2;
                remainder >>= 1;
            }
        }

        /// <summary>
        /// Generate random BigInteger from minValue to maxValue (exclude maxValue)
        /// </summary>
        private static BigInteger RandomBigInteger(BigInteger minValue, BigInteger maxValue)
        {
            Random random = new Random(123);// TODOL seed

            maxValue = maxValue - minValue;
            byte[] bytes = maxValue.ToByteArray();
            bool withSign = bytes.Length > 1 && bytes[bytes.Length - 1] == 0;

            random.NextBytes(bytes);
            if (withSign)
                bytes[bytes.Length - 1] = 0;
            BigInteger result = new BigInteger(bytes);
            if (result >= maxValue)
                result = maxValue - 1;

            return minValue + result;
        }

        

        private static ulong[] CalcPermMasks64(byte[] myTransposition)
        {
            if (myTransposition.Length > 64)
                throw new Exception("chet ne to");
            else if (myTransposition.Length < 64)
            {
                // дополнение до 64 бит
                byte[] addedTransp = new byte[64];
                HashSet<byte> indices = new HashSet<byte>();
                for (byte i = 0; i < 64; ++i)
                    indices.Add(i);
                foreach (byte usedIdex in myTransposition)
                    indices.Remove(usedIdex);

                for (int i = 0; i < 64 - myTransposition.Length; ++i)
                {
                    addedTransp[i] = indices.First();
                    indices.Remove(addedTransp[i]);
                }
                for (int i = 0; i < myTransposition.Length; ++i)
                    addedTransp[63 - i] = myTransposition[myTransposition.Length - 1 - i];
                myTransposition = addedTransp;
            }

            byte[] trueTranspose = new byte[64];
            for (int i = 0; i < 64; ++i)
                trueTranspose[myTransposition[63 - i]] = (byte)i;
            var network = new PermutationNetwork(trueTranspose);

            //tests
            Random random = new Random(123);
            byte[] buf = new byte[8];
            for (int i = 0; i < 10000; ++i)
            {
                random.NextBytes(buf);
                ulong value = BitConverter.ToUInt64(buf, 0);

                ulong expected = Bitops.BitPermutation(value, myTransposition);
                ulong actualNetwork = network.Permute(value);

                ulong actual = value;
                byte[] deltas64 = new byte[] { 1, 2, 4, 8, 16, 32, 16, 8, 4, 2, 1 };
                for (int j = 0; j < deltas64.Length; ++j)
                {
                    ulong mask = network.Masks[j];
                    if (mask != 0)
                        actual = Bitops.SwapBitsMask(actual, deltas64[j], mask);
                }

                if (expected != actualNetwork || expected != actual)
                    throw new Exception($"ne: {i}");
            }

            ulong[] masks = new ulong[11];
            for (int i = 0; i < 11; ++i)
                masks[i] = network.Masks[i];
            return masks;
        }

    }



}
