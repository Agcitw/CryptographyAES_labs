using System.Security.Cryptography;
using CryptographyLabs.Crypto.BlockCouplingModes;

namespace CryptographyLabs.Crypto
{
	public static partial class DES_
	{
		public static ICryptoTransform Get(ulong key56, byte[] IV, Mode mode, CryptoDirection direction)
		{
			switch (mode)
			{
				default:
				case Mode.ECB:
					return Get(key56, direction);
				case Mode.CBC:
					return Cbc.Get(GetNice(key56, direction), IV, direction);
				case Mode.CFB:
					return Cfb.Get(GetNice(key56, CryptoDirection.Encrypt), IV, direction);
				case Mode.OFB:
					return Ofb.Get(GetNice(key56, CryptoDirection.Encrypt), IV, direction);
			}
		}

		public static ICryptoTransform Get(ulong key56, CryptoDirection direction)
		{
			if (direction == CryptoDirection.Encrypt)
				return new DESEncryptTransform(key56);
			return new DESDecryptTransform(key56);
		}

		public static INiceCryptoTransform GetNice(ulong key56, CryptoDirection direction)
		{
			if (direction == CryptoDirection.Encrypt)
				return new DESEncryptTransform(key56);
			return new DESDecryptTransform(key56);
		}
	}
}