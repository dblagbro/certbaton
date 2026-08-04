using System.Security.Cryptography;

namespace CertBaton.Security.Windows;

public sealed class DpapiNgException : CryptographicException
{
    internal DpapiNgException(string operation, int status)
        : base($"DPAPI-NG {operation} failed with status 0x{status:X8}.")
    {
        Operation = operation;
        Status = status;
        HResult = status;
    }

    public string Operation { get; }

    public int Status { get; }
}
