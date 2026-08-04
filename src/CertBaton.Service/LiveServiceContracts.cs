using CertBaton.Application.Live;
using CertBaton.Contracts;
using CertBaton.Domain.Operations;

namespace CertBaton.Service;

public interface ILiveTargetCoordinator
{
    TargetSnapshot Enroll(TargetEnrollmentPayload payload, string actorSid);

    TargetListSnapshot List();
}

public interface ILiveRenewalCoordinator
{
    Task<RenewalOperationSnapshot> StartAsync(
        RenewalStartPayload payload,
        string actorSid,
        CancellationToken cancellationToken);

    RenewalOperationSnapshot? Find(Guid operationId);
}

public interface ILiveRenewalExecutor
{
    Task<LiveRenewalResult> RunAsync(
        OperationId operationId,
        Guid executionEpoch,
        LiveHttp01RenewalRequest request,
        CancellationToken cancellationToken);

    Task<LiveRenewalResult> RecoverAsync(
        OperationId operationId,
        Guid executionEpoch,
        LiveHttp01RenewalRequest request,
        CancellationToken cancellationToken);
}
