namespace CryptographyLabs.Crypto
{
	public interface INiceCryptoTransform
	{
		int InputBlockSize { get; }
		int OutputBlockSize { get; }
		void NiceTransform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset, int blocksCount);
        byte[] NiceFinalTransform(byte[] inputBuffer, int inputOffset, int bytesCount);
	}
}