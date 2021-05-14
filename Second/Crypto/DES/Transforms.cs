using System;
using System.Security.Cryptography;

namespace CryptographyLabs.Crypto
{
	public static partial class DES_
	{
		public const int BlockSize = 8;

		private static ulong[] GenerateKeys(ulong baseKey)
		{
			ulong key64 = 0;
			for (var i = 0; i < 8; ++i)
			{
				var bitSequence = (byte) ((baseKey >> (i * 7)) & 0b01111111);
				var xorRes = BitOperations.XorBits(bitSequence, 3);
				key64 = (key64 << 1) | (byte) (~xorRes & 1);
				key64 = (key64 << 7) | bitSequence;
			}

			var C = (uint) (BitOperations.SwapBitsMasks64(key64, _C0PermMasks) & 0xf_ff_ff_ff);
			var D = (uint) (BitOperations.SwapBitsMasks64(key64, _D0PermMasks) & 0xf_ff_ff_ff);

			ulong[] keys = new ulong[16];
			for (var i = 0; i < 16; ++i)
			{
				C = BitOperations.CycleShiftLeft(C, 28, _cycleShiftsCount[i]);
				D = BitOperations.CycleShiftLeft(D, 28, _cycleShiftsCount[i]);
				keys[i] = ((ulong) C << 28) | D;
				keys[i] = BitOperations.SwapBitsMasks64(keys[i], _keyFinalPermMasks) & 0xff_ff_ff_ff_ff_ff;
			}

			return keys;
		}

		private static ulong Encrypt(ulong text, ulong[] keys48)
		{
			text = BitOperations.SwapBitsMasks64(text, _IPPermMasks);
			var L = (uint) (text >> 32);
			var R = (uint) (text & 0xffffffff);

			for (var i = 0; i < 16; ++i)
			{
				var tm = L;
				L = R;
				R = tm ^ FeistelFunction(R, keys48[i]);
			}

			var concat = ((ulong) L << 32) | R;
			return BitOperations.SwapBitsMasks64(concat, _IPInvPermMasks);
		}

		private static ulong Decrypt(ulong crText, ulong[] keys48)
		{
			crText = BitOperations.SwapBitsMasks64(crText, _IPPermMasks);
			var L = (uint) (crText >> 32);
			var R = (uint) (crText & 0xffffffff);

			for (var i = 15; i > -1; --i)
			{
				var tm = R;
				R = L;
				L = tm ^ FeistelFunction(L, keys48[i]);
			}

			var concat = ((ulong) L << 32) | R;
			return BitOperations.SwapBitsMasks64(concat, _IPInvPermMasks);
		}

		private static uint FeistelFunction(uint value, ulong key48)
		{
			var value48 = EExpansion(value) ^ key48;

			uint SBlocksResult = 0;
			for (var i = 7; i > -1; --i)
			{
				var row = (byte) (((value48 >> (i * 6 + 4)) & 0b10) | ((value48 >> (i * 6)) & 1));
				var col = (byte) ((value48 >> (i * 6 + 1)) & 0b1111);
				SBlocksResult = (SBlocksResult << 4) | _SBlocks[8 - i - 1][row][col];
			}

			return (uint) BitOperations.SwapBitsMasks64(SBlocksResult, _PPermMasks);
		}

		private static ulong EExpansion(uint value)
		{
			ulong result = 0;
			for (var i = 0; i < 8; ++i)
				result = (result << 6) | (BitOperations.CycleShiftLeft(value, 32, (byte) (5 + i * 4)) & 0b111111);
			return result;
		}

		public class DESEncryptTransform : INiceCryptoTransform, ICryptoTransform
		{
			private readonly ulong[] _keys48;

			public DESEncryptTransform(ulong key56)
			{
				_keys48 = GenerateKeys(key56);
			}

			#region ICryptoTransform interface

			public int InputBlockSize => BlockSize;
			public int OutputBlockSize => BlockSize;
			public bool CanTransformMultipleBlocks => true;
			public bool CanReuseTransform => false;

			public void Dispose()
			{
			}

			public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
				int outputOffset)
			{
				var blocksCount = inputCount / BlockSize;
				NiceTransform(inputBuffer, inputOffset, outputBuffer, outputOffset, blocksCount);
				return blocksCount * BlockSize;
			}

			public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
			{
				return NiceFinalTransform(inputBuffer, inputOffset, inputCount);
			}

			#endregion

			#region INiceCryptoTransform interface

			public void NiceTransform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset,
				int blocksCount)
			{
				for (var i = 0; i < blocksCount; ++i)
				{
					var text = BitConverter.ToUInt64(inputBuffer, inputOffset + i * BlockSize);
					var result = Encrypt(text, _keys48);
					Array.Copy(BitConverter.GetBytes(result), 0, outputBuffer, outputOffset + i * BlockSize, BlockSize);
				}
			}

			public byte[] NiceFinalTransform(byte[] inputBuffer, int inputOffset, int bytesCount)
			{
				if (bytesCount == BlockSize)
				{
					byte[] tm = new byte[2 * BlockSize];
					Array.Copy(inputBuffer, inputOffset, tm, 0, BlockSize);
					tm[2 * BlockSize - 1] = 0;
					byte[] final = new byte[2 * BlockSize];
					NiceTransform(tm, 0, final, 0, 2);
					return final;
				}
				else
				{
					byte[] tm = new byte[BlockSize];
					Array.Copy(inputBuffer, inputOffset, tm, 0, bytesCount);
					tm[BlockSize - 1] = (byte) bytesCount;
					byte[] final = new byte[BlockSize];
					NiceTransform(tm, 0, final, 0, 1);
					return final;
				}
			}

			#endregion
		}

		public class DESDecryptTransform : INiceCryptoTransform, ICryptoTransform
		{
			private bool _isFirst = true;
			private readonly ulong[] _keys48;
			private readonly byte[] _lastBlock = new byte[BlockSize];

			public DESDecryptTransform(ulong key56)
			{
				_keys48 = GenerateKeys(key56);
			}

			#region ICryptoTransform interface

			public int InputBlockSize => BlockSize;
			public int OutputBlockSize => BlockSize;
			public bool CanTransformMultipleBlocks => true;
			public bool CanReuseTransform => false;

			public void Dispose()
			{
			}

			public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
				int outputOffset)
			{
				var blocksCount = inputCount / BlockSize;
				var offset = _isFirst ? 0 : BlockSize;
				if (!_isFirst)
				{
					var text = BitConverter.ToUInt64(_lastBlock, 0);
					var result = Decrypt(text, _keys48);
					Array.Copy(BitConverter.GetBytes(result), 0, outputBuffer, outputOffset, BlockSize);
				}

				for (var i = 0; i < blocksCount - 1; ++i)
				{
					var text = BitConverter.ToUInt64(inputBuffer, inputOffset + i * BlockSize);
					var result = Decrypt(text, _keys48);
					Array.Copy(BitConverter.GetBytes(result), 0,
						outputBuffer, outputOffset + i * BlockSize + offset, BlockSize);
				}

				Array.Copy(inputBuffer, inputOffset + blocksCount * BlockSize - BlockSize, _lastBlock, 0, BlockSize);

				if (_isFirst)
				{
					_isFirst = false;
					return (blocksCount - 1) * BlockSize;
				}

				return blocksCount * BlockSize;
			}

			public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
			{
				if (inputCount != 0)
					throw new CryptographicException("Wrong length of final block on decryption.");

				if (_isFirst)
					throw new CryptographicException("Wrong count of blocks.");

				var text = BitConverter.ToUInt64(_lastBlock, 0);
				var decryptedText = Decrypt(text, _keys48);
				byte[] decrypted = BitConverter.GetBytes(decryptedText);

				var bytesCount = decrypted[BlockSize - 1];
				byte[] result = new byte[bytesCount];
				Array.Copy(decrypted, result, bytesCount);
				return result;
			}

			#endregion

			#region INiceCryptoTransform interface

			public void NiceTransform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset,
				int blocksCount)
			{
				for (var i = 0; i < blocksCount; ++i)
				{
					var text = BitConverter.ToUInt64(inputBuffer, inputOffset + i * BlockSize);
					var result = Decrypt(text, _keys48);
					Array.Copy(BitConverter.GetBytes(result), 0,
						outputBuffer, outputOffset + i * BlockSize, BlockSize);
				}
			}

			public byte[] NiceFinalTransform(byte[] inputBuffer, int inputOffset, int bytesCount)
			{
				if (bytesCount != BlockSize)
					throw new CryptographicException("Wrong length of final block on NICE decryption.");

				byte[] final = new byte[BlockSize];
				NiceTransform(inputBuffer, inputOffset, final, 0, 1);
				Array.Resize(ref final, final[BlockSize - 1]);
				return final;
			}

			#endregion
		}
	}
}