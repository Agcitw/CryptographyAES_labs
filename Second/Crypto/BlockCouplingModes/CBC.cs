using System;
using System.Security.Cryptography;

namespace CryptographyLabs.Crypto.BlockCouplingModes
{
	public static class Cbc
	{
		public static ICryptoTransform Get(INiceCryptoTransform transform, byte[] iv, CryptoDirection direction)
		{
			if (direction == CryptoDirection.Encrypt)
				return new CbcEncryptTransform(transform, iv);
			return new CbcDecryptTransform(transform, iv);
		}
	}

	public class CbcEncryptTransform : BaseEncryptTransform
	{
		private readonly byte[] _initVector;

		public CbcEncryptTransform(INiceCryptoTransform transform, byte[] iv) : base(transform)
		{
			if (iv.Length != InputBlockSize)
				throw new ArgumentException("Wrong length of IV.");

			_initVector = new byte[InputBlockSize];
			Array.Copy(iv, _initVector, InputBlockSize);
		}

		#region BaseEncryptTransform

		protected override void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
		{
			for (var i = 0; i < InputBlockSize; i++)
				inputBuffer[inputOffset + i] ^= _initVector[i];
			BaseTransform.NiceTransform(inputBuffer, inputOffset, outputBuffer, outputOffset, 1);
			Array.Copy(outputBuffer, outputOffset, _initVector, 0, InputBlockSize);
		}

		#endregion
	}

	public class CbcDecryptTransform : BaseDecryptTransform
	{
		private readonly byte[] _initVector;

		public CbcDecryptTransform(INiceCryptoTransform transform, byte[] iv) : base(transform)
		{
			if (iv.Length != InputBlockSize)
				throw new ArgumentException("Wrong length of IV.");

			_initVector = new byte[InputBlockSize];
			Array.Copy(iv, _initVector, InputBlockSize);
		}

		#region BaseDecryptTransform

		protected override void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
		{
			BaseTransform.NiceTransform(inputBuffer, inputOffset, outputBuffer, outputOffset, 1);
			for (var i = 0; i < InputBlockSize; i++)
				outputBuffer[outputOffset + i] ^= _initVector[i];
			Array.Copy(inputBuffer, inputOffset, _initVector, 0, InputBlockSize);
		}

		#endregion
	}
}