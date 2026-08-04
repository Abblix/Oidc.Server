// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The stream store of a closed deployment: the stream set is configuration, seeded once at
/// construction, and the store holds NOTHING worth backing up. Right where the receivers are
/// the operator's own products - the lifecycle lives in configuration, not in the management
/// API.
/// </summary>
/// <remarks>
/// Mutations through the API are accepted but ephemeral: a status change or a verification
/// timestamp lives until the process restarts, then the configuration is truth again. That is
/// the deliberate trade of this store - the one field that must move at runtime, the
/// verification throttle, tolerates loss by construction (one extra verification is allowed),
/// and everything durable is the operator's file. A deployment that needs receiver-driven
/// lifecycle registers a durable <see cref="IStreamStore"/> instead.
/// </remarks>
public sealed class ConfigurationStreamStore : IStreamStore
{
    private readonly InMemoryStreamStore _streams = new();

    /// <summary>
    /// Materializes the configured streams: the transmitter's half - issuer, supported and
    /// delivered sets, the poll endpoint - comes from <paramref name="options"/>, exactly as
    /// the dynamic create would supply it.
    /// </summary>
    /// <param name="options">The deployment's one-time decisions.</param>
    /// <param name="streams">The declared streams.</param>
    /// <exception cref="InvalidOperationException">
    /// Two declarations share a receiver and stream identifier, or a poll stream is declared on
    /// a transmitter with no poll endpoint factory - configuration bugs, refused loudly at
    /// startup rather than surfacing as a broken stream later.</exception>
    public ConfigurationStreamStore(SsfTransmitterOptions options, IReadOnlyList<ConfiguredStream> streams)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(streams);

        foreach (var declared in streams)
        {
            // The in-memory seed answers synchronously; AsTask keeps the wait an ordinary,
            // rule-clean one for the constructor's single pass.
            var created = _streams.TryCreateAsync(Materialize(options, declared)).AsTask();
            if (!created.GetAwaiter().GetResult())
            {
                throw new InvalidOperationException(
                    $"The stream '{declared.StreamId}' of receiver '{declared.ReceiverId}' is declared "
                    + "more than once.");
            }
        }
    }

    /// <inheritdoc />
    public ValueTask<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => _streams.TryCreateAsync(stream, cancellationToken);

    /// <inheritdoc />
    public ValueTask<StreamState?> FindAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
        => _streams.FindAsync(receiverId, streamId, cancellationToken);

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<StreamState>> ListAsync(
        string receiverId,
        CancellationToken cancellationToken = default)
        => _streams.ListAsync(receiverId, cancellationToken);

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
        => _streams.ListAllAsync(cancellationToken);

    /// <inheritdoc />
    public ValueTask<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => _streams.UpdateAsync(stream, cancellationToken);

    /// <inheritdoc />
    public ValueTask<bool> DeleteAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
        => _streams.DeleteAsync(receiverId, streamId, cancellationToken);

    private static StreamState Materialize(SsfTransmitterOptions options, ConfiguredStream declared)
    {
        StreamDeliveryMethod delivery;
        if (declared.PushEndpointUrl is { } pushEndpoint)
        {
            delivery = new PushDeliveryMethod(pushEndpoint)
            {
                AuthorizationHeader = declared.PushAuthorizationHeader,
            };
        }
        else if (options.PollEndpointFactory is { } pollEndpointOf)
        {
            delivery = new PollDeliveryMethod(pollEndpointOf(declared.StreamId));
        }
        else
        {
            throw new InvalidOperationException(
                $"The stream '{declared.StreamId}' declares no push endpoint and the transmitter "
                + $"offers no poll delivery: set {nameof(ConfiguredStream.PushEndpointUrl)} or "
                + $"{nameof(SsfTransmitterOptions)}.{nameof(SsfTransmitterOptions.PollEndpointFactory)}.");
        }

        return new StreamState
        {
            ReceiverId = declared.ReceiverId,
            SubjectsMode = declared.SubjectsMode,
            Configuration = new StreamConfiguration
            {
                StreamId = declared.StreamId,
                Issuer = options.Issuer,
                Audiences = declared.Audiences.Length > 0 ? declared.Audiences : [declared.ReceiverId],
                EventsSupported = options.EventsSupported is { Count: > 0 } supported ? supported : null,
                EventsRequested = declared.EventsRequested.Length > 0 ? declared.EventsRequested : null,
                EventsDelivered =
                [
                    .. declared.EventsRequested.Where(eventType =>
                        options.EventsSupported.Contains(eventType, StringComparer.Ordinal)),
                ],
                Delivery = delivery,
                MinVerificationInterval = options.MinVerificationInterval,
                Description = declared.Description,
            },
        };
    }
}
