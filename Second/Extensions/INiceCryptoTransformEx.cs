using System;
using System.Threading;
using CryptographyLabs.Crypto;

namespace CryptographyLabs.Extensions
{
	public static class NiceCryptoTransformEx
	{
		public static void NiceTransform(this INiceCryptoTransform transform, byte[] inputBuffer, int inputOffset,
			byte[] outputBuffer, int outputOffset, int blocksCount, Action<double> progressCallback = null)
		{
			for (var i = 0; i < blocksCount; i++)
			{
				transform.NiceTransform(inputBuffer, inputOffset + i * transform.InputBlockSize,
					outputBuffer, outputOffset + i * transform.OutputBlockSize, 1);
				progressCallback?.Invoke((double) (i + 1) / blocksCount);
			}
		}

        public static void NiceTransform(this INiceCryptoTransform transform, byte[] inputBuffer, int inputOffset,
			byte[] outputBuffer, int outputOffset, int blocksCount, CancellationToken token,
			Action<double> progressCallback = null)
		{
			for (var i = 0; i < blocksCount; i++)
			{
				token.ThrowIfCancellationRequested();
				transform.NiceTransform(inputBuffer, inputOffset + i * transform.InputBlockSize,
					outputBuffer, outputOffset + i * transform.OutputBlockSize, 1);
				progressCallback?.Invoke((double) (i + 1) / blocksCount);
			}
		}
	}
}