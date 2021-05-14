using System;
using System.IO;
using System.Windows;
using CryptographyLabs.Crypto;
using CryptographyLabs.Crypto.Rijndael;
using Microsoft.WindowsAPICodePack.Dialogs;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CryptographyLabs.GUI.MainWindow.Crypto
{
	internal abstract class RijndaelVm : BaseViewModel
	{
		private const string JKeyForIv = "iv";
		private const string JKeyForKey = "key";

		protected abstract void ChangeFilePath();

		protected abstract void Go();

		private void LoadKey()
		{
			using var dialog = new CommonOpenFileDialog();
			dialog.EnsureFileExists = true;
			dialog.Filters.Add(new CommonFileDialogFilter("Json", "*.json"));
			if (dialog.ShowDialog() != CommonFileDialogResult.Ok)
				return;

			try
			{
				var text = File.ReadAllText(dialog.FileName);
				var obj = (JObject) JsonConvert.DeserializeObject(text);
				if (obj == null) return;
				var key = obj.Value<string>(JKeyForKey);
				var iv = obj.Value<string>(JKeyForIv);
				Key = key;
				Iv = iv;
			}
			catch (Exception e)
			{
				MessageBox.Show($"Error: {e.Message}");
			}
		}

		private void SaveKey()
		{
			using var dialog = new CommonSaveFileDialog();
			dialog.Filters.Add(new CommonFileDialogFilter("Json file", ".json"));
			dialog.DefaultExtension = "json";
			if (dialog.ShowDialog() != CommonFileDialogResult.Ok)
				return;

			JObject obj = new(new JProperty(JKeyForKey, Key), new JProperty(JKeyForIv, Iv));

			try
			{
				File.WriteAllText(dialog.FileName, obj.ToString(Formatting.Indented));
			}
			catch (Exception e)
			{
				MessageBox.Show($"Error: {e.Message}");
			}
		}

		#region Bindings

		public Rijndael.Mode Mode { get; private set; } = Rijndael.Mode.Ecb;

		public int ModeIndex
		{
			get => (int) Mode;
			set
			{
				Mode = (Rijndael.Mode) value;
				NotifyPropChanged(nameof(ModeIndex), nameof(Mode));
			}
		}

		private bool _multithreading;

		public bool Multithreading
		{
			get => _multithreading;
			set
			{
				_multithreading = value;
				NotifyPropChanged(nameof(Multithreading));
			}
		}

		protected Rijndael.Size BlockSize { get; private set; }

		public int BlockSizeIndex
		{
			get => (int) BlockSize;
			set
			{
				BlockSize = (Rijndael.Size) value;
				NotifyPropChanged(nameof(BlockSizeIndex));
			}
		}

		protected Rijndael.Size KeySize { get; private set; }

		public int KeySizeIndex
		{
			get => (int) KeySize;
			set
			{
				KeySize = (Rijndael.Size) value;
				NotifyPropChanged(nameof(KeySizeIndex));
			}
		}

		private string _filePath = "";

		public string FilePath
		{
			get => _filePath;
			set
			{
				_filePath = value;
				NotifyPropChanged(nameof(FilePath));
			}
		}

		private RelayCommand _changeFilePathCmd;

		public RelayCommand ChangeFilePathCmd
			=> _changeFilePathCmd ??= new RelayCommand(_ => ChangeFilePath());

		private string _key = "";

		public string Key
		{
			get => _key;
			set
			{
				_key = value;
				NotifyPropChanged(nameof(Key));
			}
		}

		private string _iv = "";

		public string Iv
		{
			get => _iv;
			set
			{
				_iv = value;
				NotifyPropChanged(nameof(Iv));
			}
		}

		private bool _isDeleteAfter;

		public bool IsDeleteAfter
		{
			get => _isDeleteAfter;
			set
			{
				_isDeleteAfter = value;
				NotifyPropChanged(nameof(IsDeleteAfter));
			}
		}

		private RelayCommand _loadKeyCmd;

		public RelayCommand LoadKeyCmd
			=> _loadKeyCmd ??= new RelayCommand(_ => LoadKey());

		private RelayCommand _saveKeyCmd;

		public RelayCommand SaveKeyCmd
			=> _saveKeyCmd ??= new RelayCommand(_ => SaveKey());

		private RelayCommand _goCmd;

		public RelayCommand GoCmd
			=> _goCmd ??= new RelayCommand(_ => Go());

		#endregion
	}
}