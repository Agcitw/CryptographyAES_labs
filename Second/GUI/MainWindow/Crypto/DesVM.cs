using System;
using System.IO;
using System.Windows;
using CryptographyLabs.Crypto;
using Microsoft.WindowsAPICodePack.Dialogs;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CryptographyLabs.GUI.MainWindow.Crypto
{
	public class DesVm : BaseViewModel
	{
		private const string JKeyForIv = "iv";

		private const string JKeyForKey = "key";

		private void LoadKey()
		{
			using var dialog = new CommonOpenFileDialog {EnsureFileExists = true};
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

		public DES_.Mode Mode { get; private set; } = DES_.Mode.ECB;

		public int ModeIndex
		{
			get => (int) Mode;
			set
			{
				Mode = (DES_.Mode) value;
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

		private RelayCommand _loadKeyCmd;

		public RelayCommand LoadKeyCmd
			=> _loadKeyCmd ??= new RelayCommand(_ => LoadKey());

		private RelayCommand _saveKeyCmd;

		public RelayCommand SaveKeyCmd
			=> _saveKeyCmd ??= new RelayCommand(_ => SaveKey());

		private bool _isDeleteFileAfter;

		public bool IsDeleteFileAfter
		{
			get => _isDeleteFileAfter;
			set
			{
				_isDeleteFileAfter = value;
				NotifyPropChanged(nameof(IsDeleteFileAfter));
			}
		}

		#endregion
	}
}