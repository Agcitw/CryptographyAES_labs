using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CryptographyLabs.Extensions
{
	public static class StreamEx
	{
		public static async Task CopyToAsync(this Stream from, Stream destination, int bufSize,
			CancellationToken token, Action<double> progressCallback = null)
		{
			progressCallback?.Invoke(0);
			var buffer = new byte[bufSize];
			long totalWrote = 0;
			while (true)
			{
				if (token.IsCancellationRequested)
					token.ThrowIfCancellationRequested();

				var hasRead = await from.ReadAsync(buffer, 0, bufSize, token);
				if (hasRead == 0)
					break;
				await destination.WriteAsync(buffer, 0, hasRead, token);
				totalWrote += hasRead;
				progressCallback?.Invoke((double) totalWrote / from.Length);
			}
			progressCallback?.Invoke(1);
		}
	}
}