using System;
using System.Security.Cryptography;

namespace CryptographyLabs.Crypto.BlockCouplingModes
{
	public static class Cfb
	{
		public static ICryptoTransform Get(INiceCryptoTransform transform, byte[] iv, CryptoDirection direction)
		{
			if (direction == CryptoDirection.Encrypt)
				return new CfbEncryptTransform(transform, iv);
			return new CfbDecryptTransform(transform, iv);
		}

		private class CfbEncryptTransform : BaseEncryptTransform
		{
			private readonly byte[] _initVector;

			public CfbEncryptTransform(INiceCryptoTransform transform, byte[] iv) : base(transform)
			{
				if (iv.Length != InputBlockSize)
					throw new ArgumentException("Wrong length of IV.");

				_initVector = new byte[InputBlockSize];
				Array.Copy(iv, _initVector, InputBlockSize);
			}

			#region BaseEncryptTransform

			protected override void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer,
				int outputOffset)
			{
				BaseTransform.NiceTransform(_initVector, 0, outputBuffer, outputOffset, 1);
				for (var i = 0; i < InputBlockSize; i++)
					outputBuffer[outputOffset + i] ^= inputBuffer[inputOffset + i];
				Array.Copy(outputBuffer, outputOffset, _initVector, 0, InputBlockSize);
			}

			#endregion
		}

		private class CfbDecryptTransform : BaseDecryptTransform
		{
			private readonly byte[] _initVector;

			public CfbDecryptTransform(INiceCryptoTransform transform, byte[] iv) : base(transform)
			{
				if (iv.Length != InputBlockSize)
					throw new ArgumentException("Wrong length of IV.");

				_initVector = new byte[InputBlockSize];
				Array.Copy(iv, _initVector, InputBlockSize);
			}

			#region BaseEncryptTransform

			protected override void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer,
				int outputOffset)
			{
				BaseTransform.NiceTransform(_initVector, 0, outputBuffer, outputOffset, 1);
				Array.Copy(inputBuffer, inputOffset, _initVector, 0, InputBlockSize);
				for (var i = 0; i < InputBlockSize; i++)
					outputBuffer[outputOffset + i] ^= inputBuffer[inputOffset + i];
			}

			#endregion
		}
	}
}