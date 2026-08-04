namespace CertBaton.Service;

public static class ServiceStatePath
{
    public const string MaintenanceMarkerFileName = "maintenance.lock";

    public static string ResolveDatabasePath(bool isInstalledWindowsService)
    {
        var root = Environment.GetFolderPath(
            isInstalledWindowsService
                ? Environment.SpecialFolder.CommonApplicationData
                : Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException(
                "Windows did not provide the required application-data location.");
        }

        var stateDirectory = isInstalledWindowsService
            ? Path.Combine(root, "CertBaton", "State")
            : Path.Combine(root, "CertBaton", "Development", "State");

        if (isInstalledWindowsService)
        {
            if (!Directory.Exists(stateDirectory))
            {
                throw new InvalidOperationException(
                    "The protected CertBaton state directory is missing. Repair the installation before starting the service.");
            }

            InstalledStateSecurityValidator.Validate(stateDirectory);
        }
        else
        {
            _ = Directory.CreateDirectory(stateDirectory);

            var attributes = File.GetAttributes(stateDirectory);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException(
                    "The CertBaton state directory cannot be a reparse point.");
            }
        }

        return Path.Combine(stateDirectory, "certbaton.db");
    }

    public static string ResolveSecretsDirectory(bool isInstalledWindowsService)
    {
        var root = Environment.GetFolderPath(
            isInstalledWindowsService
                ? Environment.SpecialFolder.CommonApplicationData
                : Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException(
                "Windows did not provide the required application-data location.");
        }

        var secretsDirectory = isInstalledWindowsService
            ? Path.Combine(root, "CertBaton", "Secrets")
            : Path.Combine(root, "CertBaton", "Development", "Secrets");
        if (isInstalledWindowsService)
        {
            if (!Directory.Exists(secretsDirectory))
            {
                throw new InvalidOperationException(
                    "The protected CertBaton secrets directory is missing. Repair the installation before starting the service.");
            }

            InstalledStateSecurityValidator.Validate(secretsDirectory);
        }
        else
        {
            _ = Directory.CreateDirectory(secretsDirectory);
            var attributes = File.GetAttributes(secretsDirectory);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException(
                    "The CertBaton secrets directory cannot be a reparse point.");
            }
        }

        return secretsDirectory;
    }

    public static string ResolveMaintenanceMarkerPath(
        bool isInstalledWindowsService)
    {
        var root = Environment.GetFolderPath(
            isInstalledWindowsService
                ? Environment.SpecialFolder.CommonApplicationData
                : Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException(
                "Windows did not provide the required application-data location.");
        }

        var dataDirectory = isInstalledWindowsService
            ? Path.Combine(root, "CertBaton")
            : Path.Combine(root, "CertBaton", "Development");
        return Path.Combine(dataDirectory, MaintenanceMarkerFileName);
    }
}
