using System;
using System.Security.Cryptography;

namespace CryptographyLabs.Crypto.BlockCouplingModes
{
	public abstract class BaseDecryptTransform : ICryptoTransform
	{
		protected readonly INiceCryptoTransform BaseTransform;
		private readonly byte[] _prevText;
		private byte _prevTextsCount;

		protected BaseDecryptTransform(INiceCryptoTransform transform)
		{
			if (transform.InputBlockSize != transform.OutputBlockSize)
				throw new CryptographicException("InputBlockSize != OutputBlockSize.");

			BaseTransform = transform;
			_prevText = new byte[2 * InputBlockSize];
		}

		#region ICryptoTransform

		public int InputBlockSize => BaseTransform.InputBlockSize;
		public int OutputBlockSize => BaseTransform.OutputBlockSize;
		public bool CanTransformMultipleBlocks => true;
		public bool CanReuseTransform => false;

		public void Dispose()
		{
		}

		public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
			int outputOffset)
		{
			var blocksCount = inputCount / InputBlockSize;

			switch (blocksCount)
			{
				case 0:
					return 0;
				case 1 when _prevTextsCount == 2:
					Transform(_prevText, 0, outputBuffer, outputOffset);
					Array.Copy(_prevText, InputBlockSize, _prevText, 0, InputBlockSize);
					Array.Copy(inputBuffer, inputOffset, _prevText, InputBlockSize, InputBlockSize);
					return InputBlockSize;
				case 1:
					Array.Copy(inputBuffer, inputOffset, _prevText,
						_prevTextsCount * InputBlockSize, InputBlockSize);
					_prevTextsCount++;
					return 0;
			}

			for (var i = 0; i < _prevTextsCount; i++)
				Transform(_prevText, i * InputBlockSize,
					outputBuffer, outputOffset + i * InputBlockSize);

			for (var i = 0; i < blocksCount - 2; i++)
				Transform(inputBuffer, inputOffset + i * InputBlockSize,
					outputBuffer, (i + _prevTextsCount) * InputBlockSize);

			Array.Copy(inputBuffer, inputOffset + (blocksCount - 2) * InputBlockSize,
				_prevText, 0, InputBlockSize);
			Array.Copy(inputBuffer, inputOffset + (blocksCount - 1) * InputBlockSize,
				_prevText, InputBlockSize, InputBlockSize);

			var blocksTransformed = blocksCount - 2 + _prevTextsCount;
			_prevTextsCount = 2;
			return blocksTransformed * InputBlockSize;
		}

		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			if (inputCount != 0)
				throw new CryptographicException("Wrong length of final block on OFB decryption.");

			switch (_prevTextsCount)
			{
				case 0:
					throw new CryptographicException("Wrong count of blocks on OFB decryption.");
				case 1:
				{
					var buf = new byte[InputBlockSize];
					Transform(_prevText, 0, buf, 0);
					if (buf[0] != 0)
						throw new CryptographicException("Final block is broken.");
					return Array.Empty<byte>();
				}
				default:
				{
					var buf = new byte[2 * InputBlockSize];
					Transform(_prevText, 0, buf, 0);
					Transform(_prevText, InputBlockSize, buf, InputBlockSize);
					if (buf[InputBlockSize] > InputBlockSize)
						throw new CryptographicException("Final block is broken.");
					Array.Resize(ref buf, buf[InputBlockSize]);
					return buf;
				}
			}
		}

		protected abstract void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset);

		#endregion
	}
}