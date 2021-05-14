using System.Windows;
using CryptographyLabs.Crypto;
using CryptographyLabs.Extensions;
using CryptographyLabs.GUI.MainWindow.Progress;
using Microsoft.WindowsAPICodePack.Dialogs;

namespace CryptographyLabs.GUI.MainWindow.Crypto
{
	public class DesEncryptVm : BaseViewModel
	{
		private readonly MainWindowVm _owner;

		public DesEncryptVm(DesVm desVm, MainWindowVm owner)
		{
			DesVm = desVm;
			_owner = owner;
		}

		public DesVm DesVm { get; }

		private void ChangeFilename()
		{
			using var dialog = new CommonOpenFileDialog();
			dialog.Filters.Add(new CommonFileDialogFilter("Any file", "*"));
			if (dialog.ShowDialog() == CommonFileDialogResult.Ok)
				FilenameToEncrypt = dialog.FileName;
		}

		private void GoEncrypt()
		{
			if (!StringEx.TryParse(DesVm.Key, out ulong key56))
			{
				MessageBox.Show("Wrong key format.", "Error");
				return;
			}

			var filePath = FilenameToEncrypt;
			var encryptPath = filePath + ".des";

			BaseTransformVm vm;
			if (DesVm.Mode == DES_.Mode.ECB)
			{
				vm = new DesEncryptTransformVm(filePath, encryptPath, key56, DesVm.IsDeleteFileAfter,
					DesVm.Multithreading);
			}
			else
			{
				if (!StringEx.TryParse(DesVm.Iv, out byte[] IV))
				{
					MessageBox.Show("Wrong IV format.");
					return;
				}

				if (IV.Length != DES_.BlockSize)
				{
					MessageBox.Show($"Wrong IV bytes count. Must be {DES_.BlockSize}.");
					return;
				}

				vm = new DesEncryptTransformVm(filePath, encryptPath, key56, IV, DesVm.Mode, DesVm.IsDeleteFileAfter);
			}

			_owner.ProgressViewModels.Add(vm);
		}

		#region Bindings

		private string _filenameToEncrypt = "";

		public string FilenameToEncrypt
		{
			get => _filenameToEncrypt;
			set
			{
				_filenameToEncrypt = value;
				NotifyPropChanged(nameof(FilenameToEncrypt));
			}
		}

		private RelayCommand _changeFilenameCmd;

		public RelayCommand ChangeFilenameCmd =>
			_changeFilenameCmd ??= new RelayCommand(_ => ChangeFilename());

		private RelayCommand _goEncryptCmd;

		public RelayCommand GoEncryptCmd
			=> _goEncryptCmd ??= new RelayCommand(_ => GoEncrypt());

		#endregion
	}
}