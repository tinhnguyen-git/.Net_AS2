using Net.AS2.Core.Settings;
using Serilog.Core;

namespace Net.AS2.Core.Helper
{
	public interface ILogFileWriter
    {
		void FileName(string logFileName);
		Task WriteLog(string msg);
		Task WriteLog(string msg, string logFileName);
	}

	public class LogFileWriter: ILogFileWriter
	{
		private string _logFileName;
		private readonly FileLocation _fileLocation;
		public LogFileWriter(FileLocation fileLocation)
        {
			_fileLocation = fileLocation;
		}

		public void FileName(string logFileName)
		{
			_logFileName = logFileName;
		}

		public async Task WriteLog(string msg)
		{
			if(string.IsNullOrEmpty(_logFileName))
            {
				FileName("NoName");
            }
			await WriteLog(msg, _logFileName);
		}
		public async Task WriteLog(string msg, string logFileName)
		{
			try
			{
				string logFile = Path.Combine(_fileLocation.LogStored, logFileName);
				if (!string.IsNullOrEmpty(msg.Trim()))
				{
					var fileStream = File.Exists(logFile)
						? new FileStream(logFile, FileMode.Append, FileAccess.Write, FileShare.ReadWrite)
						: new FileStream(logFile, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite);

					var streamWriter = new StreamWriter(fileStream);
					if (fileStream.Length >= _fileLocation.LogFileSizeLimit)
					{
						streamWriter.Close();
						string extension = Path.GetExtension(logFile);
						string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(logFile);
						string[] mLogArchiveDirectory = { _fileLocation.LogStored, "/", fileNameWithoutExtension, "_End_", DateTime.UtcNow.ToString("yy_MM_dd_HHmmss"), extension };

						string str = string.Concat(mLogArchiveDirectory);
						File.Copy(logFile, str, true);
						if (File.Exists(logFile))
						{
							streamWriter.Close();
							fileStream.Close();
							File.Delete(logFile);
						}
						fileStream = new FileStream(logFile, FileMode.OpenOrCreate, FileAccess.Write);
						streamWriter = new StreamWriter(fileStream);
					}
					await streamWriter.WriteLineAsync(string.Concat(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"), " ", msg));
					streamWriter.Close();
				}
			}
			catch (Exception exception)
			{
				Serilog.Log.Logger.Error(exception, "LogFileWriter");
			}
		}
	}
}
