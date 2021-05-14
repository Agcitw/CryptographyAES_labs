using CryptographyLabs.Crypto;

namespace CryptographyLabs.GUI.MainWindow.Progress
{
	internal class DesEncryptTransformVm : BaseTransformVm
	{
		public DesEncryptTransformVm(string filePath, string encryptFilePath, ulong key56, byte[] IV,
			DES_.Mode mode, bool isDeleteAfter) : base(isDeleteAfter, CryptoDirection.Encrypt)
		{
			CryptoName = "DES";
			SourceFilePath = filePath;
			DestFilePath = encryptFilePath;

			Start(DES_.Get(key56, IV, mode, CryptoDirection.Encrypt));
		}

		public DesEncryptTransformVm(string filePath, string encryptFilePath, ulong key56, bool isDeleteAfter,
			bool multithreading = false)
			: base(isDeleteAfter, CryptoDirection.Encrypt)
		{
			CryptoName = "DES";
			SourceFilePath = filePath;
			DestFilePath = encryptFilePath;

			if (multithreading)
				StartMultithreading(DES_.GetNice(key56, CryptoDirection.Encrypt));
			else
				Start(DES_.Get(key56, CryptoDirection.Encrypt));
		}
	}
}