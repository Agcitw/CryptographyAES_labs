using CryptographyLabs.Crypto;

namespace CryptographyLabs.GUI.MainWindow.Progress
{
	internal class DesDecryptTransformVm : BaseTransformVm
	{
		public DesDecryptTransformVm(string filePath, string decryptFilePath, ulong key56, byte[] IV, DES_.Mode mode,
			bool isDeleteAfter) : base(isDeleteAfter, CryptoDirection.Decrypt)
		{
			CryptoName = "DES";
			SourceFilePath = filePath;
			DestFilePath = decryptFilePath;

			Start(DES_.Get(key56, IV, mode, CryptoDirection.Decrypt));
		}

		public DesDecryptTransformVm(string filePath, string decryptFilePath, ulong key56, bool isDeleteAfter,
			bool multithreading = false)
			: base(isDeleteAfter, CryptoDirection.Decrypt)
		{
			CryptoName = "DES";
			SourceFilePath = filePath;
			DestFilePath = decryptFilePath;

			if (multithreading)
				StartMultithreading(DES_.GetNice(key56, CryptoDirection.Decrypt));
			else
				Start(DES_.Get(key56, CryptoDirection.Decrypt));
		}
	}
}