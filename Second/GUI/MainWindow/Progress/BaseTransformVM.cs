using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CryptographyLabs.Crypto;
using CryptographyLabs.Crypto.BlockCouplingModes;
using CryptographyLabs.Extensions;

namespace CryptographyLabs.GUI.MainWindow.Progress
{
	public abstract class BaseTransformVm : BaseViewModel
	{
		private readonly CancellationTokenSource _cts = new();
		private readonly CryptoDirection? _direction;

		private readonly bool _isDeleteAfter;

		protected BaseTransformVm(bool isDeleteAfter, CryptoDirection? direction)
		{
			_isDeleteAfter = isDeleteAfter;
			_direction = direction;
		}

		protected async void Start(ICryptoTransform transform)
		{
			StatusString = _direction switch
			{
				null => "...",
				CryptoDirection.Encrypt => "Encryption...",
				_ => "Decryption..."
			};

			try
			{
				await MakeTransform(transform);
				await DeleteSourceIfNeeded();
				OnDoneSuccessfully();
			}
			catch (OperationCanceledException)
			{
				OnCanceled();
			}
			catch (Exception e)
			{
				OnError(e.Message);
			}
		}

		private async Task MakeTransform(ICryptoTransform transform)
		{
			OperationCanceledException canceledException = null;

			try
			{
				await using FileStream inStream = new(SourceFilePath, FileMode.Open, FileAccess.Read);
				await using FileStream outStream = new(DestFilePath, FileMode.Create, FileAccess.Write);
				await using CryptoStream outCrypto = new(outStream, transform, CryptoStreamMode.Write);
				try
				{
					await inStream.CopyToAsync(outCrypto, 80_000, _cts.Token,
						progress => CryptoProgress = progress);
				}
				catch (OperationCanceledException e)
				{
					canceledException = e;
				}
			}
			catch (Exception)
			{
				if (canceledException is null)
					throw;
			}
			if (canceledException != null)
				throw canceledException;
		}

		protected async void StartMultithreading(INiceCryptoTransform transform)
		{
			try
			{
				StatusString = "Reading file...";
				var text = await File.ReadAllBytesAsync(SourceFilePath, _cts.Token);
				StatusString = _direction switch
				{
					null => "...",
					CryptoDirection.Encrypt => "Encryption...",
					_ => "Decryption..."
				};
				var transformed = await Ecb.TransformAsync(text, transform, _cts.Token, 4,
					progress => CryptoProgress = progress);
				StatusString = "Saving to file...";
				await File.WriteAllBytesAsync(DestFilePath, transformed, _cts.Token);
				await DeleteSourceIfNeeded();
				OnDoneSuccessfully();
			}
			catch (OperationCanceledException)
			{
				OnCanceled();
			}
			catch (Exception e)
			{
				OnError(e.Message);
			}
		}

		private async Task DeleteSourceIfNeeded()
		{
			if (_isDeleteAfter)
			{
				StatusString = "Deleting file...";
				await Task.Run(() => File.Delete(SourceFilePath));
			}
		}

		private void Cancel()
		{
			_cts.Cancel();
		}

		private void OnCanceled()
		{
			Reject();
			StatusString = "Canceled";
			IsDone = true;
		}

		private void OnError(string msg)
		{
			Reject();
			StatusString = "Error: " + msg;
			IsDone = true;
		}

		private void OnDoneSuccessfully()
		{
			StatusString = "Done successfully";
			IsDone = true;
		}

		private void Reject()
		{
			if (File.Exists(DestFilePath))
				File.Delete(DestFilePath);
		}

		#region Bindings

		private string _sourceFilePath = "";

		public string SourceFilePath
		{
			get => _sourceFilePath;
			set
			{
				_sourceFilePath = value;
				NotifyPropChanged(nameof(SourceFilePath));
			}
		}

		private string _destFilePath;

		public string DestFilePath
		{
			get => _destFilePath;
			set
			{
				_destFilePath = value;
				NotifyPropChanged(nameof(DestFilePath));
			}
		}

		private string _statusString = "aga";

		public string StatusString
		{
			get => _statusString;
			set
			{
				_statusString = value;
				NotifyPropChanged(nameof(StatusString));
			}
		}

		private double _cryptoProgress;

		public double CryptoProgress
		{
			get => _cryptoProgress;
			set
			{
				_cryptoProgress = value switch
				{
					> 100 => 100,
					< 0 => 0,
					_ => value
				};
				NotifyPropChanged(nameof(CryptoProgress));
			}
		}

		private bool _isDone;

		public bool IsDone
		{
			get => _isDone;
			set
			{
				_isDone = value;
				NotifyPropChanged(nameof(IsDone));
			}
		}

		private string _cryptoName = "";

		public string CryptoName
		{
			get => _cryptoName;
			set
			{
				_cryptoName = value;
				NotifyPropChanged(nameof(CryptoName));
			}
		}

		private RelayCommand _cancelCmd;

		public RelayCommand CancelCmd
			=> _cancelCmd ??= new RelayCommand(_ => Cancel());

		#endregion
	}
}