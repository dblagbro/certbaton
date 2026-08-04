using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using CertBaton.Application.Remote;
using CertBaton.Application.Simulation.Persistence;
using CertBaton.Contracts;
using CertBaton.Ipc.NamedPipes;
using CertBaton.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertBaton.UnitTests;

[TestClass]
public sealed class LiveIpcWorkerTests
{
    [TestMethod]
    public async Task AdministratorCanTestSshSftpConnectionWithoutPersistingKey()
    {
        var options = CreateOptions(PipeServerSecurityProfile.InstalledService);
        var probe = new StubSshConnectionProbe();
        var worker = CreateWorker(options, null, null, sshConnectionProbe: probe);
        var key =
            "-----BEGIN PRIVATE KEY-----\nprobe\n-----END PRIVATE KEY-----"u8.ToArray();
        var request = IpcRequest.CreateSshConnectionProbe(
            TimeProvider.System,
            new SshConnectionProbePayload(
                "SSH.EXAMPLE.TEST.",
                22,
                "designer",
                key));

        var response = await worker.HandleRequestAsync(
            request,
            CreateIdentity(isAdministrator: true),
            CancellationToken.None);

        Assert.IsTrue(response.Success);
        Assert.AreEqual("ssh.example.test", response.Result?.SshConnectionProbe?.Host);
        Assert.IsTrue(response.Result?.SshConnectionProbe?.SftpAvailable);
        Assert.AreEqual(key.Length, probe.PrivateKeyLength);
        Assert.IsTrue(
            request.SshConnectionProbePayload!.PrivateKey.All(
                static value => value == 0));
    }

    [TestMethod]
    public async Task OrdinaryUserCannotTestHostingConnectionAndKeyIsZeroed()
    {
        var options = CreateOptions(PipeServerSecurityProfile.InstalledService);
        var probe = new StubSshConnectionProbe();
        var worker = CreateWorker(options, null, null, sshConnectionProbe: probe);
        var request = IpcRequest.CreateSshConnectionProbe(
            TimeProvider.System,
            new SshConnectionProbePayload(
                "ssh.example.test",
                22,
                "designer",
                "private-key"u8.ToArray()));

        var response = await worker.HandleRequestAsync(
            request,
            CreateIdentity(isAdministrator: false),
            CancellationToken.None);

        Assert.IsFalse(response.Success);
        Assert.AreEqual("connection_probe_forbidden", response.Error?.Code);
        Assert.AreEqual(0, probe.PrivateKeyLength);
        Assert.IsTrue(
            request.SshConnectionProbePayload!.PrivateKey.All(
                static value => value == 0));
    }

    [TestMethod]
    public async Task InstalledServiceDeniesOrdinaryLiveEnrollmentBeforePersistence()
    {
        var options = CreateOptions(
            PipeServerSecurityProfile.InstalledService);
        var targets = new StubTargetCoordinator();
        var worker = CreateWorker(options, targets, null);
        var request = IpcRequest.CreateTargetEnrollment(
            TimeProvider.System,
            CreateEnrollmentPayload());

        var response = await worker.HandleRequestAsync(
            request,
            CreateIdentity(isAdministrator: false),
            CancellationToken.None);

        Assert.IsFalse(response.Success);
        Assert.AreEqual("target_enroll_forbidden", response.Error?.Code);
        Assert.AreEqual(0, targets.EnrollCalls);
    }

    [TestMethod]
    public async Task AdministratorCanEnrollAndListLiveTarget()
    {
        var options = CreateOptions(
            PipeServerSecurityProfile.InstalledService);
        var targets = new StubTargetCoordinator();
        var worker = CreateWorker(options, targets, null);
        var identity = CreateIdentity(isAdministrator: true);
        var enrollment = CreateEnrollmentPayload();

        var enrolled = await worker.HandleRequestAsync(
            IpcRequest.CreateTargetEnrollment(
                TimeProvider.System,
                enrollment),
            identity,
            CancellationToken.None);
        var listed = await worker.HandleRequestAsync(
            IpcRequest.CreateTargetList(TimeProvider.System),
            identity,
            CancellationToken.None);

        Assert.IsTrue(enrolled.Success);
        Assert.AreEqual(enrollment.EnrollmentId, enrolled.Result?.Target?.TargetId);
        Assert.AreEqual(identity.UserSid, targets.ActorSid);
        Assert.IsTrue(listed.Success);
        var listedTargets = listed.Result?.TargetList?.Targets;
        Assert.IsNotNull(listedTargets);
        Assert.HasCount(1, listedTargets);
    }

    [TestMethod]
    public async Task LiveRenewalStartAndGetUseTypedIdentifiers()
    {
        var options = CreateOptions(
            PipeServerSecurityProfile.CurrentUserDevelopment);
        var targetId = Guid.CreateVersion7();
        var operationId = Guid.CreateVersion7();
        var renewals = new StubRenewalCoordinator(
            CreateQueuedOperation(operationId, targetId));
        var worker = CreateWorker(options, null, renewals);
        var identity = CreateIdentity(isAdministrator: false);
        var idempotencyKey = Guid.CreateVersion7();

        var started = await worker.HandleRequestAsync(
            IpcRequest.CreateRenewalStart(
                TimeProvider.System,
                new RenewalStartPayload(targetId, idempotencyKey)),
            identity,
            CancellationToken.None);
        var found = await worker.HandleRequestAsync(
            IpcRequest.CreateRenewalGet(
                TimeProvider.System,
                new RenewalQueryPayload(operationId)),
            identity,
            CancellationToken.None);

        Assert.IsTrue(started.Success);
        Assert.IsTrue(found.Success);
        Assert.AreEqual(targetId, renewals.TargetId);
        Assert.AreEqual(idempotencyKey, renewals.IdempotencyKey);
        Assert.AreEqual(operationId, renewals.FindOperationId);
    }

    [TestMethod]
    public async Task MaintenanceMarkerBlocksEveryStateChangingIpcMethod()
    {
        var directory = Directory.CreateTempSubdirectory(
            "CertBaton.IpcMaintenance-").FullName;
        try
        {
            var markerPath = Path.Combine(directory, "maintenance.lock");
            await File.WriteAllTextAsync(markerPath, "maintenance");
            var gate = new LiveMaintenanceGate(markerPath);
            var options = CreateOptions(
                PipeServerSecurityProfile.CurrentUserDevelopment);
            var targets = new StubTargetCoordinator();
            var renewals = new StubRenewalCoordinator(
                CreateQueuedOperation(Guid.CreateVersion7(), Guid.CreateVersion7()));
            var worker = CreateWorker(options, targets, renewals, gate);
            var identity = CreateIdentity(isAdministrator: false);
            var secret = "-----BEGIN PRIVATE KEY-----\nunit-test"u8.ToArray();
            var credentialRequest =
                IpcRequest.CreateCredentialImportSshPrivateKey(
                    TimeProvider.System,
                    secret);
            var requests = new[]
            {
                credentialRequest,
                IpcRequest.CreateTargetEnrollment(
                    TimeProvider.System,
                    CreateEnrollmentPayload()),
                IpcRequest.CreateRenewalStart(
                    TimeProvider.System,
                    new RenewalStartPayload(
                        Guid.CreateVersion7(),
                        Guid.CreateVersion7())),
                IpcRequest.CreateSimulationStart(
                    TimeProvider.System,
                    Guid.CreateVersion7()),
            };

            foreach (var request in requests)
            {
                var response = await worker.HandleRequestAsync(
                    request,
                    identity,
                    CancellationToken.None);

                Assert.IsFalse(response.Success);
                Assert.AreEqual("service_maintenance", response.Error?.Code);
            }

            Assert.AreEqual(0, targets.EnrollCalls);
            Assert.AreEqual(Guid.Empty, renewals.TargetId);
            Assert.IsTrue(
                credentialRequest.CredentialPayload!.Secret.All(
                    static value => value == 0));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static IpcWorker CreateWorker(
        IpcServerOptions options,
        ILiveTargetCoordinator? targets,
        ILiveRenewalCoordinator? renewals,
        LiveMaintenanceGate? maintenanceGate = null,
        ISshConnectionProbe? sshConnectionProbe = null) =>
        new(
            new CertBatonPipeServer(options),
            new NullSimulationCoordinator(),
            new SimulationAccessPolicy(options),
            NullLogger<IpcWorker>.Instance,
            TimeProvider.System,
            sshConnectionProbe: sshConnectionProbe,
            liveTargetCoordinator: targets,
            liveRenewalCoordinator: renewals,
            maintenanceGate: maintenanceGate);

    private static IpcServerOptions CreateOptions(
        PipeServerSecurityProfile profile) =>
        new()
        {
            PipeName = $"CertBaton.UnitTests.{Guid.NewGuid():N}",
            SecurityProfile = profile,
        };

    private static PipeClientIdentity CreateIdentity(bool isAdministrator) =>
        new(
            isAdministrator ? "S-1-5-32-544" : "S-1-5-32-545",
            isAdministrator,
            TokenImpersonationLevel.Identification);

    private static TargetEnrollmentPayload CreateEnrollmentPayload()
    {
        var rawKey = RandomNumberGenerator.GetBytes(48);
        return new TargetEnrollmentPayload(
            Guid.CreateVersion7(),
            "Example target",
            ["www2.example.test"],
            "ssh.example.test",
            22,
            "certbaton",
            Guid.CreateVersion7(),
            "ssh-ed25519",
            "SHA256:" + Convert.ToBase64String(SHA256.HashData(rawKey)).TrimEnd('='),
            Convert.ToBase64String(rawKey),
            "/srv/www/challenges",
            "/srv/certbaton/incoming",
            "/srv/certbaton/releases/current/fullchain.pem",
            "/srv/certbaton/releases/current/privkey.pem",
            LiveContractValues.LetsEncryptStaging,
            "operator@example.test",
            true,
            true,
            20,
            720);
    }

    private static TargetSnapshot ToTarget(
        TargetEnrollmentPayload payload) =>
        new(
            payload.EnrollmentId,
            payload.DisplayName,
            payload.DnsNames,
            payload.Host,
            payload.Port,
            payload.Username,
            payload.HostKeyAlgorithm,
            payload.HostKeyFingerprintSha256,
            payload.CertificateAuthority,
            payload.AutoRenew,
            null,
            "ready");

    private static RenewalOperationSnapshot CreateQueuedOperation(
        Guid operationId,
        Guid targetId)
    {
        var now = DateTimeOffset.UtcNow;
        return new RenewalOperationSnapshot(
            operationId,
            targetId,
            "queued",
            now,
            now,
            null,
            null,
            null,
            false,
            false,
            []);
    }

    private sealed class StubTargetCoordinator : ILiveTargetCoordinator
    {
        private TargetSnapshot? target;

        public int EnrollCalls { get; private set; }

        public string? ActorSid { get; private set; }

        public TargetSnapshot Enroll(
            TargetEnrollmentPayload payload,
            string actorSid)
        {
            EnrollCalls++;
            ActorSid = actorSid;
            target = ToTarget(payload);
            return target;
        }

        public TargetListSnapshot List() =>
            new(target is null ? [] : [target]);
    }

    private sealed class StubRenewalCoordinator(
        RenewalOperationSnapshot operation) : ILiveRenewalCoordinator
    {
        public Guid TargetId { get; private set; }

        public Guid IdempotencyKey { get; private set; }

        public Guid FindOperationId { get; private set; }

        public Task<RenewalOperationSnapshot> StartAsync(
            RenewalStartPayload payload,
            string actorSid,
            CancellationToken cancellationToken)
        {
            _ = actorSid;
            cancellationToken.ThrowIfCancellationRequested();
            TargetId = payload.TargetId;
            IdempotencyKey = payload.IdempotencyKey;
            return Task.FromResult(operation);
        }

        public RenewalOperationSnapshot? Find(Guid operationId)
        {
            FindOperationId = operationId;
            return operation.OperationId == operationId ? operation : null;
        }
    }

    private sealed class StubSshConnectionProbe : ISshConnectionProbe
    {
        public int PrivateKeyLength { get; private set; }

        public Task<SshConnectionProbeResult> ProbeAsync(
            RemoteSshEndpoint endpoint,
            RemotePrivateKeyMaterial privateKey,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var stream = privateKey.OpenReadStream();
            PrivateKeyLength = checked((int)stream.Length);
            var hostKey = RandomNumberGenerator.GetBytes(48);
            return Task.FromResult(
                new SshConnectionProbeResult(
                    endpoint,
                    "ssh-ed25519",
                    "SHA256:" +
                        Convert.ToBase64String(SHA256.HashData(hostKey)).TrimEnd('='),
                    Convert.ToBase64String(hostKey),
                    AuthenticationSucceeded: true,
                    SftpAvailable: true));
        }
    }

    private sealed class NullSimulationCoordinator : ISimulationCoordinator
    {
        public SimulationJobDetails? Latest => null;

        public Task<SimulationJobDetails> StartAsync(
            Guid idempotencyKey,
            CertBaton.Domain.Renewals.RenewalStage? failureStage,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException();
    }
}
