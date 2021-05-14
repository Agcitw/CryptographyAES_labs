using CryptographyLabs.Crypto;
using CryptographyLabs.Crypto.Rijndael;

namespace CryptographyLabs.GUI.MainWindow.Progress
{
	internal class RijndaelEncryptTransformVm : BaseTransformVm
	{
		public RijndaelEncryptTransformVm(string filePath, string encryptFilePath, byte[] key,
			Rijndael.Size blockSize, bool isDeleteAfter, bool multithreading = false)
			: base(isDeleteAfter, CryptoDirection.Encrypt)
		{
			CryptoName = "Rijndael";
			SourceFilePath = filePath;
			DestFilePath = encryptFilePath;

			if (multithreading)
				StartMultithreading(Rijndael.GetNice(key, blockSize, CryptoDirection.Encrypt));
			else
				Start(Rijndael.Get(key, blockSize, CryptoDirection.Encrypt));
		}

		public RijndaelEncryptTransformVm(string filePath, string encryptFilePath, byte[] key,
			Rijndael.Size blockSize, byte[] iv, Rijndael.Mode mode, bool isDeleteAfter)
			: base(isDeleteAfter, CryptoDirection.Encrypt)
		{
			CryptoName = "Rijndael";
			SourceFilePath = filePath;
			DestFilePath = encryptFilePath;

			Start(Rijndael.Get(key, blockSize, iv, mode, CryptoDirection.Encrypt));
		}
	}
}