using System.Windows;
using CryptographyLabs.Crypto;
using CryptographyLabs.Crypto.Rijndael;
using CryptographyLabs.Extensions;
using CryptographyLabs.GUI.MainWindow.Progress;
using Microsoft.WindowsAPICodePack.Dialogs;

namespace CryptographyLabs.GUI.MainWindow.Crypto
{
	internal class RijndaelDecryptVm : RijndaelVm
	{
		private readonly MainWindowVm _owner;

		public RijndaelDecryptVm(MainWindowVm owner)
		{
			_owner = owner;
		}

		protected override void ChangeFilePath()
		{
			using var dialog = new CommonOpenFileDialog();
			dialog.Filters.Add(new CommonFileDialogFilter("Encrypted file", ".rjn"));
			if (dialog.ShowDialog() == CommonFileDialogResult.Ok)
				FilePath = dialog.FileName;
		}

		protected override void Go()
		{
			if (!StringEx.TryParse(Key, out byte[] keyBytes))
			{
				MessageBox.Show("Wrong key format.");
				return;
			}

			if (keyBytes.Length != Rijndael.GetBytesCount(KeySize))
			{
				MessageBox.Show("Wrong bytes count in key.");
				return;
			}

			string decryptPath;
			if (FilePath.EndsWith(".rjn"))
			{
				decryptPath = FilePath.Substring(0, FilePath.Length - 7);
			}
			else
			{
				MessageBox.Show("Wrong extenstion of encrypted file. Must be \".rjn\".");
				return;
			}

			BaseTransformVm vm;
			if (Mode == Rijndael.Mode.Ecb)
			{
				vm = new RijndaelDecryptTransformVm(FilePath, decryptPath, keyBytes, BlockSize, IsDeleteAfter,
					Multithreading);
			}
			else
			{
				if (!StringEx.TryParse(Iv, out byte[] iv))
				{
					MessageBox.Show("Wrong IV format.");
					return;
				}

				if (iv.Length != Rijndael.GetBytesCount(BlockSize))
				{
					MessageBox.Show($"Wrong IV bytes count. Must be {Rijndael.GetBytesCount(BlockSize)}.");
					return;
				}

				vm = new RijndaelDecryptTransformVm(FilePath, decryptPath, keyBytes,
					BlockSize, iv, Mode, IsDeleteAfter);
			}

			_owner.ProgressViewModels.Add(vm);
		}
	}
}