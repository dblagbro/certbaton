namespace CertBaton.Service;

public static class ServiceStatePath
{
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
}
