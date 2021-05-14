using System.Security.Cryptography;

namespace CryptographyLabs.Crypto
{
	public abstract class BlockEncryptTransform : INiceCryptoTransform, ICryptoTransform
	{
		protected BlockEncryptTransform(int blockSize) : this(blockSize, blockSize)
		{
		}

		private BlockEncryptTransform(int inputBlockSize, int outputBlockSize)
		{
			InputBlockSize = inputBlockSize;
			OutputBlockSize = outputBlockSize;
		}

		protected abstract void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset);

		#region ICryptoTransform

		public int InputBlockSize { get; }

		public int OutputBlockSize { get; }

		public bool CanTransformMultipleBlocks => true;
		public bool CanReuseTransform => false;

		public abstract void Dispose();

		public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
			int outputOffset)
		{
			var blocksCount = inputCount / InputBlockSize;
			NiceTransform(inputBuffer, inputOffset, outputBuffer, outputOffset, blocksCount);
			return blocksCount * OutputBlockSize;
		}

		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			inputBuffer[InputBlockSize - 1] = (byte) inputCount;
			var final = new byte[OutputBlockSize];
			Transform(inputBuffer, inputOffset, final, 0);
			return final;
		}

		#endregion

		#region INiceCryptoTransform

		public void NiceTransform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset,
			int blocksCount)
		{
			for (var i = 0; i < blocksCount; i++)
				Transform(inputBuffer, inputOffset + i * InputBlockSize,
					outputBuffer, outputOffset + i * OutputBlockSize);
		}

		public byte[] NiceFinalTransform(byte[] inputBuffer, int inputOffset, int bytesCount)
		{
			if (bytesCount == InputBlockSize)
			{
				var tm = new byte[InputBlockSize];
				tm[InputBlockSize - 1] = 0;

				var final = new byte[2 * OutputBlockSize];
				Transform(inputBuffer, inputOffset, final, 0);
				Transform(tm, 0, final, OutputBlockSize);
				return final;
			}
			else
			{
				inputBuffer[InputBlockSize - 1] = (byte) bytesCount;
				var final = new byte[OutputBlockSize];
				Transform(inputBuffer, inputOffset, final, 0);
				return final;
			}
		}

		#endregion
	}
}