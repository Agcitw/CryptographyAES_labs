using System;
using System.Security.Cryptography;

namespace CryptographyLabs.Crypto.BlockCouplingModes
{
	public static class Ofb
	{
		public static ICryptoTransform Get(INiceCryptoTransform transform, byte[] iv, CryptoDirection direction)
		{
			if (direction == CryptoDirection.Encrypt)
				return new OfbEncryptTransform(transform, iv);
			return new OfbDecryptTransform(transform, iv);
		}
	}

	public class OfbEncryptTransform : BaseEncryptTransform
	{
		private readonly byte[] _initVector;

		public OfbEncryptTransform(INiceCryptoTransform transform, byte[] IV) : base(transform)
		{
			if (IV.Length != InputBlockSize)
				throw new ArgumentException("Wrong length of IV.");

			_initVector = new byte[InputBlockSize];
			Array.Copy(IV, _initVector, InputBlockSize);
		}

		#region BaseDecryptTransform

		protected override void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
		{
			BaseTransform.NiceTransform(_initVector, 0, outputBuffer, outputOffset, 1);
			Array.Copy(outputBuffer, outputOffset, _initVector, 0, InputBlockSize);
			for (var i = 0; i < InputBlockSize; i++)
				outputBuffer[outputOffset + i] ^= inputBuffer[inputOffset + i];
		}

		#endregion
	}

	public class OfbDecryptTransform : BaseDecryptTransform
	{
		private readonly byte[] _initVector;

		public OfbDecryptTransform(INiceCryptoTransform transform, byte[] iv) : base(transform)
		{
			if (iv.Length != InputBlockSize)
				throw new ArgumentException("Wrong length of IV.");

			_initVector = new byte[InputBlockSize];
			Array.Copy(iv, _initVector, InputBlockSize);
		}

		#region BaseDecryptTransform

		protected override void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
		{
			BaseTransform.NiceTransform(_initVector, 0, outputBuffer, outputOffset, 1);
			Array.Copy(outputBuffer, outputOffset, _initVector, 0, InputBlockSize);
			for (var i = 0; i < InputBlockSize; i++)
				outputBuffer[outputOffset + i] ^= inputBuffer[inputOffset + i];
		}

		#endregion
	}
}