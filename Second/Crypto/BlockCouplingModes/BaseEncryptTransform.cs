using System.Security.Cryptography;

namespace CryptographyLabs.Crypto.BlockCouplingModes
{
	public abstract class BaseEncryptTransform : ICryptoTransform
	{
		protected readonly INiceCryptoTransform BaseTransform;
		private bool _hasBlocks;

		protected BaseEncryptTransform(INiceCryptoTransform transform)
		{
			if (transform.InputBlockSize != transform.OutputBlockSize)
				throw new CryptographicException("InputBlockSize != OutputBlockSize.");

			BaseTransform = transform;
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
			if (blocksCount > 0 && !_hasBlocks)
				_hasBlocks = true;

			for (var i = 0; i < blocksCount; i++)
				Transform(inputBuffer, inputOffset + i * InputBlockSize,
					outputBuffer, outputOffset + i * InputBlockSize);
			return blocksCount * InputBlockSize;
		}

		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			if (inputCount == 0)
			{
				byte[] buf = new byte[InputBlockSize];
				if (_hasBlocks)
					buf[0] = 8;
				else
					buf[0] = 0;
				var final = new byte[InputBlockSize];
				Transform(buf, 0, final, 0);
				return final;
			}
			else
			{
				var final = new byte[2 * InputBlockSize];
				Transform(inputBuffer, inputOffset, final, 0);

				var buf = new byte[InputBlockSize];
				buf[0] = (byte) inputCount;
				Transform(buf, 0, final, InputBlockSize);

				return final;
			}
		}

		protected abstract void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset);

		#endregion
	}
}