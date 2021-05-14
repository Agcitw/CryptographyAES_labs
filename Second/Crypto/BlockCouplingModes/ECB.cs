using System;
using System.Threading;
using System.Threading.Tasks;
using CryptographyLabs.Extensions;

namespace CryptographyLabs.Crypto.BlockCouplingModes
{
	public static class Ecb
	{
        public static async Task<byte[]> TransformAsync(byte[] data, INiceCryptoTransform transform,
			CancellationToken token, int threadsCount = 4, Action<double> progressCallback = null)
		{
			if (data.Length == 0)
				throw new ArgumentException("Length of text if empty.");

			var blocksCount = data.Length / transform.InputBlockSize;
			var lastBlockSize = data.Length % transform.InputBlockSize;
			if (lastBlockSize == 0)
			{
				blocksCount--;
				lastBlockSize = transform.InputBlockSize;
			}

			var result = new byte[blocksCount * transform.OutputBlockSize];

			var blocksPerThread = blocksCount / threadsCount;
			var transformTasks = new Task[threadsCount];
			var progresses = new double[threadsCount];
			for (var i = 0; i < threadsCount; i++)
			{
				var currentBlocksCount = i == threadsCount - 1
					? blocksPerThread + blocksCount % threadsCount
					: blocksPerThread;

				var i_ = i;
				transformTasks[i] = MakeTransformTask(transform, data, i * blocksPerThread * transform.InputBlockSize,
					result, i * blocksPerThread * transform.OutputBlockSize, currentBlocksCount, token,
					progress =>
					{
						progresses[i_] = progress;
						progressCallback?.Invoke(MathEx.Sum(progresses) / threadsCount);
					});
			}

			var finalTask = Task.Run(() =>
			{
				var buf = new byte[transform.InputBlockSize];
				Array.Copy(data, blocksCount * transform.InputBlockSize, buf, 0, lastBlockSize);
				return transform.NiceFinalTransform(buf, 0, lastBlockSize);
			});

			await Task.WhenAll(transformTasks);
			var final = await finalTask;

			Array.Resize(ref result, result.Length + final.Length);
			Array.Copy(final, 0, result, blocksCount * transform.OutputBlockSize, final.Length);
			return result;
		}

        private static Task MakeTransformTask(INiceCryptoTransform transform, byte[] inBuf, int inOffset,
			byte[] outBuf, int outOffset, int blocksCount, CancellationToken token,
			Action<double> progressCallback = null)
		{
			return Task.Run(() =>
			{
				transform.NiceTransform(inBuf, inOffset, outBuf, outOffset, blocksCount, token, progressCallback);
			});
		}
        
		public static async Task<byte[]> TransformAsync(byte[] data, INiceCryptoTransform transform,
			int threadsCount = 4, Action<double> progressCallback = null)
		{
			if (data.Length == 0)
				throw new ArgumentException("Length of text if empty.");

			var blocksCount = data.Length / transform.InputBlockSize;
			var lastBlockSize = data.Length % transform.InputBlockSize;
			if (lastBlockSize == 0)
			{
				blocksCount--;
				lastBlockSize = transform.InputBlockSize;
			}

			var result = new byte[blocksCount * transform.OutputBlockSize];

			var blocksPerThread = blocksCount / threadsCount;
			var transformTasks = new Task[threadsCount];
			var progresses = new double[threadsCount];
			for (var i = 0; i < threadsCount; i++)
			{
				var currentBlocksCount = i == threadsCount - 1
					? blocksPerThread + blocksCount % threadsCount
					: blocksPerThread;

				var i_ = i;
				transformTasks[i] = MakeTransformTask(transform, data, i * blocksPerThread * transform.InputBlockSize,
					result, i * blocksPerThread * transform.OutputBlockSize, currentBlocksCount,
					progress =>
					{
						progresses[i_] = progress;
						progressCallback?.Invoke(MathEx.Sum(progresses) / threadsCount);
					});
			}

			var finalTask = Task.Run(() =>
			{
				var buf = new byte[transform.InputBlockSize];
				Array.Copy(data, blocksCount * transform.InputBlockSize, buf, 0, lastBlockSize);
				return transform.NiceFinalTransform(buf, 0, lastBlockSize);
			});

			await Task.WhenAll(transformTasks);
			var final = await finalTask;

			Array.Resize(ref result, result.Length + final.Length);
			Array.Copy(final, 0, result, blocksCount * transform.OutputBlockSize, final.Length);
			return result;
		}

		private static Task MakeTransformTask(INiceCryptoTransform transform, byte[] inBuf, int inOffset,
			byte[] outBuf, int outOffset, int blocksCount, Action<double> progressCallback = null)
		{
			return Task.Run(() =>
			{
				transform.NiceTransform(inBuf, inOffset, outBuf, outOffset, blocksCount, progressCallback);
			});
		}
	}
}