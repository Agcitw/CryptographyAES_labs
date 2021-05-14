using System.Collections.ObjectModel;
using CryptographyLabs.GUI.MainWindow.Crypto;
using CryptographyLabs.GUI.MainWindow.Progress;

namespace CryptographyLabs.GUI.MainWindow
{
	public class MainWindowVm : BaseViewModel
	{
		public MainWindowVm()
		{
			_rijndaelEncryptVm = new RijndaelEncryptVm(this);
			_rijndaelDecryptVm = new RijndaelDecryptVm(this);
			
			var desVm = new DesVm();
			_desEncryptVm = new DesEncryptVm(desVm, this);
			_desDecryptVm = new DesDecryptVm(desVm, this);

			UpdateRijndaelVm();
			UpdateDesVm();
		}

		private void UpdateRijndaelVm()
		{
			if (_rijndaelIsEncrypt)
				RijndaelVm = _rijndaelEncryptVm;
			else
				RijndaelVm = _rijndaelDecryptVm;
		}
		private void UpdateDesVm()
		{
			if (DesIsEncrypt)
				DesVm = _desEncryptVm;
			else
				DesVm = _desDecryptVm;
		}

		#region Bindings

		private readonly DesEncryptVm _desEncryptVm;
		private readonly DesDecryptVm _desDecryptVm;

		private bool _desIsEncrypt = true;

		public bool DesIsEncrypt
		{
			get => _desIsEncrypt;
			set
			{
				if (value == _desIsEncrypt)
					return;
				_desIsEncrypt = value;
				NotifyPropChanged(nameof(DesIsEncrypt));
				UpdateDesVm();
			}
		}

		private BaseViewModel _desVm;

		public BaseViewModel DesVm
		{
			get => _desVm;
			set
			{
				_desVm = value;
				NotifyPropChanged(nameof(DesVm));
			}
		}

		private readonly RijndaelEncryptVm _rijndaelEncryptVm;
		private readonly RijndaelDecryptVm _rijndaelDecryptVm;

		private bool _rijndaelIsEncrypt = true;

		public bool RijndaelIsEncrypt
		{
			get => _rijndaelIsEncrypt;
			set
			{
				if (value == _rijndaelIsEncrypt)
					return;
				_rijndaelIsEncrypt = value;
				NotifyPropChanged(nameof(RijndaelIsEncrypt));
				UpdateRijndaelVm();
			}
		}

		private BaseViewModel _rijndaelVm;

		public BaseViewModel RijndaelVm
		{
			get => _rijndaelVm;
			set
			{
				_rijndaelVm = value;
				NotifyPropChanged(nameof(RijndaelVm));
			}
		}

		private ObservableCollection<BaseTransformVm> _progressViewModels;

		public ObservableCollection<BaseTransformVm> ProgressViewModels =>
			_progressViewModels ??= new ObservableCollection<BaseTransformVm>();

		#endregion
	}
}