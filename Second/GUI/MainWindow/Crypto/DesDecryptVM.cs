using System.Windows;
using CryptographyLabs.Crypto;
using CryptographyLabs.Extensions;
using CryptographyLabs.GUI.MainWindow.Progress;
using Microsoft.WindowsAPICodePack.Dialogs;

namespace CryptographyLabs.GUI.MainWindow.Crypto
{
	public class DesDecryptVm : BaseViewModel
	{
		private readonly MainWindowVm _owner;

		public DesDecryptVm(DesVm desVm, MainWindowVm owner)
		{
			DesVm = desVm;
			_owner = owner;
		}

		public DesVm DesVm { get; }

		private void ChangeFilename()
		{
			using var dialog = new CommonOpenFileDialog();
			dialog.Filters.Add(new CommonFileDialogFilter("Encrypted file", ".des"));
			if (dialog.ShowDialog() == CommonFileDialogResult.Ok)
				FilenameToDecrypt = dialog.FileName;
		}

		private void GoDecrypt()
		{
			if (!StringEx.TryParse(DesVm.Key, out ulong key56))
			{
				MessageBox.Show("Wrong key format.", "Error");
				return;
			}
			var filePath = FilenameToDecrypt;
			string decryptPath;
			if (filePath.EndsWith(".des"))
			{
				decryptPath = filePath[..^7];
			}
			else
			{
				MessageBox.Show("Wrong extension of file.");
				return;
			}
			BaseTransformVm vm;
			if (DesVm.Mode == DES_.Mode.ECB)
			{
				vm = new DesDecryptTransformVm(filePath, decryptPath, key56, DesVm.IsDeleteFileAfter,
					DesVm.Multithreading);
			}
			else
			{
				if (!StringEx.TryParse(DesVm.Iv, out byte[] iv))
				{
					MessageBox.Show("Wrong IV format.");
					return;
				}

				if (iv.Length != DES_.BlockSize)
				{
					MessageBox.Show($"Wrong IV bytes count. Must be {DES_.BlockSize}.");
					return;
				}
				vm = new DesDecryptTransformVm(filePath, decryptPath, key56, iv, DesVm.Mode, DesVm.IsDeleteFileAfter);
			}

			_owner.ProgressViewModels.Add(vm);
		}

		#region Bindings

		private string _filenameToDecrypt = "";
		public string FilenameToDecrypt
		{
			get => _filenameToDecrypt;
			set
			{
				_filenameToDecrypt = value;
				NotifyPropChanged(nameof(FilenameToDecrypt));
			}
		}
		private RelayCommand _changeFilenameCmd;
		public RelayCommand ChangeFilenameCmd =>
			_changeFilenameCmd ??= new RelayCommand(_ => ChangeFilename());
		private RelayCommand _goDecryptCmd;
		public RelayCommand GoDecryptCmd
			=> _goDecryptCmd ??= new RelayCommand(_ => GoDecrypt());

		#endregion
	}
}