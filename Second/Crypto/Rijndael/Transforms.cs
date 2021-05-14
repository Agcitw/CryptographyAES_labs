using System;
using System.Collections.Generic;
using CryptographyLabs.Extensions;

namespace CryptographyLabs.Crypto.Rijndael
{
	public static partial class Rijndael
	{
		private static byte[][] GenerateRoundKeys(byte[] baseKey, int roundsCount, int nb, int nk)
		{
			var wordsCount = (roundsCount + 1) * nb;
			byte[][] words = new byte[wordsCount][];
			for (var i = 0; i < nk; i++)
			{
				words[i] = new byte[4];
				Array.Copy(baseKey, 4 * i, words[i], 0, 4);
			}

			for (var i = nk; i < wordsCount; i++)
			{
				words[i] = new byte[4];

				byte[] temp = new byte[4];
				Array.Copy(words[i - 1], temp, 4);

				if (i % nk == 0)
				{
					RotWord(temp);
					SubBytes(temp);
					temp[0] ^= Rc(i / nk - 1);
				}
				else if (nk == 8 && i % nk == 4)
				{
					SubBytes(temp);
				}

				Array.Copy(words[i - nk], words[i], 4);
				for (var j = 0; j < 4; j++)
					words[i][j] ^= temp[j];
			}

			var roundKeys = ArrayEx.Transform(words, roundsCount + 1);
			return roundKeys;
		}

		private static void RotWord(IList<byte> word)
		{
			var tm = word[0];
			for (var i = 0; i < word.Count - 1; i++)
				word[i] = word[i + 1];
			word[^1] = tm;
		}

		private static void AddRoundKey(IList<byte> state, int offset, byte[] key)
		{
			for (var i = 0; i < key.Length; i++)
				state[offset + i] ^= key[i];
		}

		private static void SubBytes(byte[] state)
		{
			Replace(state, _sBox);
		}

		private static void Replace(IList<byte> values, int offset, int count, byte[] replaceBox)
		{
			for (var i = offset; i < offset + count; i++)
				values[i] = replaceBox[values[i]];
		}

		private static void Replace(IList<byte> values, byte[] replaceBox)
		{
			for (var i = 0; i < values.Count; i++)
				values[i] = replaceBox[values[i]];
		}

		private static void MixColumns(IList<byte> state, int offset, int nb, byte[][] mtx)
		{
			for (var col = 0; col < nb; col++)
			{
				byte[] resVector = new byte[4];
				for (var bIndex = 0; bIndex < 4; bIndex++)
				for (var j = 0; j < 4; j++)
					resVector[bIndex] ^= Gf.Multiply(mtx[bIndex][j], state[offset + j * nb + col]);

				for (var j = 0; j < 4; j++)
					state[offset + j * nb + col] = resVector[j];
			}
		}

		private static byte Rc(int i)
		{
			var x = (ushort) (1 << i);
			return Gf.Mod(x);
		}

		public class RijndaelEncryptTransform : BlockEncryptTransform
		{
			private readonly int _nb;
			private readonly byte[][] _roundKeys;
			private readonly int _roundsCount;

			public RijndaelEncryptTransform(Size stateSize, byte[] key) : base(GetBytesCount(stateSize))
			{
				var keySize = SizeByBytesCount(key.Length);
				_roundsCount = GetRoundsCount(stateSize, keySize);
				_nb = InputBlockSize / 4;
				var nk = key.Length / 4;

				_roundKeys = GenerateRoundKeys(key, _roundsCount, _nb, nk);
			}

			private void SubBytes(IList<byte> bytes, int offset)
			{
				Replace(bytes, offset, InputBlockSize, _sBox);
			}

			private void MixColumns(IList<byte> state, int offset)
			{
				Rijndael.MixColumns(state, offset, _nb, _mixColumnMatrix);
			}

			private void ShiftRow(IList<byte> state, int offset)
			{
				byte[] saved = new byte[3];
				for (var row = 1; row < 4; row++)
				{
					for (var j = 0; j < row; j++)
						saved[j] = state[offset + row * _nb + j];

					for (var col = 0; col < _nb - row; col++)
						state[offset + row * _nb + col] = state[offset + row * _nb + col + row];

					for (var j = 0; j < row; j++)
						state[offset + row * _nb + _nb - row + j] = saved[j];
				}
			}

			#region BlockEncryptTransform

			public override void Dispose()
			{
			}

			protected override void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer,
				int outputOffset)
			{
				Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset, InputBlockSize);
				AddRoundKey(outputBuffer, outputOffset, _roundKeys[0]);

				for (var round = 1; round < _roundsCount; round++)
				{
					SubBytes(outputBuffer, outputOffset);
					ShiftRow(outputBuffer, outputOffset);
					MixColumns(outputBuffer, outputOffset);
					AddRoundKey(outputBuffer, outputOffset, _roundKeys[round]);
				}

				SubBytes(outputBuffer, outputOffset);
				ShiftRow(outputBuffer, outputOffset);

				AddRoundKey(outputBuffer, outputOffset, _roundKeys[_roundsCount]);
			}

			#endregion
		}

		public class RijndaelDecryptTransform : BlockDecryptTransform
		{
			private readonly int _nb;
			private readonly byte[][] _roundKeys;
			private readonly int _roundsCount;

			public RijndaelDecryptTransform(Size stateSize, byte[] key)
				: base(GetBytesCount(stateSize))
			{
				var keySize = SizeByBytesCount(key.Length);
				_roundsCount = GetRoundsCount(stateSize, keySize);
				_nb = InputBlockSize / 4;
				var nk = key.Length / 4;

				_roundKeys = GenerateRoundKeys(key, _roundsCount, _nb, nk);
			}

			private void InvSubBytes(IList<byte> bytes, int offset)
			{
				Replace(bytes, offset, InputBlockSize, _invSBox);
			}

			private void InvMixColumns(IList<byte> state, int offset)
			{
				MixColumns(state, offset, _nb, _invMixColumnMatrix);
			}

			private void InvShiftRow(IList<byte> state, int offset)
			{
				var saved = new byte[3];
				for (var row = 1; row < 4; row++)
				{
					for (var j = row - 1; j >= 0; j--)
						saved[j] = state[offset + (row + 1) * _nb - j - 1];

					for (var col = _nb - 1; col >= row; col--)
						state[offset + row * _nb + col] = state[offset + row * _nb + col - row];

					for (var j = row - 1; j >= 0; j--)
						state[offset + row * _nb + row - j - 1] = saved[j];
				}
			}

			#region BlockDecryptTransform

			public override void Dispose()
			{
			}

			protected override void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer,
				int outputOffset)
			{
				Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset, InputBlockSize);
				AddRoundKey(outputBuffer, outputOffset, _roundKeys[_roundsCount]);

				for (var round = _roundsCount - 1; round >= 1; round--)
				{
					InvShiftRow(outputBuffer, outputOffset);
					InvSubBytes(outputBuffer, outputOffset);
					AddRoundKey(outputBuffer, outputOffset, _roundKeys[round]);
					InvMixColumns(outputBuffer, outputOffset);
				}

				InvShiftRow(outputBuffer, outputOffset);
				InvSubBytes(outputBuffer, outputOffset);
				AddRoundKey(outputBuffer, outputOffset, _roundKeys[0]);
			}

			#endregion
		}
	}
}