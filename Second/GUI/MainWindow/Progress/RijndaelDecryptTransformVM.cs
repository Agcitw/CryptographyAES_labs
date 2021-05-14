using CryptographyLabs.Crypto;
using CryptographyLabs.Crypto.Rijndael;

namespace CryptographyLabs.GUI.MainWindow.Progress
{
	internal class RijndaelDecryptTransformVm : BaseTransformVm
	{
		public RijndaelDecryptTransformVm(string filePath, string decryptFilePath, byte[] key,
			Rijndael.Size blockSize, bool isDeleteAfter, bool multithreading = false)
			: base(isDeleteAfter, CryptoDirection.Decrypt)
		{
			CryptoName = "Rijndael";
			SourceFilePath = filePath;
			DestFilePath = decryptFilePath;

			if (multithreading)
				StartMultithreading(Rijndael.GetNice(key, blockSize, CryptoDirection.Decrypt));
			else
				Start(Rijndael.Get(key, blockSize, CryptoDirection.Decrypt));
		}

		public RijndaelDecryptTransformVm(string filePath, string decryptFilePath, byte[] key,
			Rijndael.Size blockSize, byte[] iv, Rijndael.Mode mode, bool isDeleteAfter)
			: base(isDeleteAfter, CryptoDirection.Decrypt)
		{
			CryptoName = "Rijndael";
			SourceFilePath = filePath;
			DestFilePath = decryptFilePath;

			Start(Rijndael.Get(key, blockSize, iv, mode, CryptoDirection.Decrypt));
		}
	}
}