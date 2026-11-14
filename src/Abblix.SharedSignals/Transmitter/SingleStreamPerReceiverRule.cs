// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The one-stream-per-receiver policy of SSF 1.0 Section 8.1.1.1 (Specification), asked twice by a
/// create: once before the stream exists, and once after, to settle a race two creates both passed.
/// </summary>
/// <param name="store">Where streams live.</param>
/// <param name="options">Says whether the policy is in force at all.</param>
internal sealed class SingleStreamPerReceiverRule(IStreamStore store, SharedSignalsTransmitterOptions options)
{
    /// <summary>
    /// Whether the receiver may not have another stream, judged before one is created.
    /// </summary>
    public async Task<bool> ForbidsAnotherAsync(string receiverId, CancellationToken cancellationToken)
        => !options.AllowMultipleStreamsPerReceiver
           && (await store.ListAsync(receiverId, cancellationToken)).Count > 0;

    /// <summary>
    /// Whether the stream just created must withdraw because another one of the same receiver won.
    /// </summary>
    /// <remarks>
    /// The count <see cref="ForbidsAnotherAsync"/> read was taken before this stream existed, and the
    /// identifier is freshly generated, so nothing collides and two creates arriving together both pass.
    /// Re-read now that ours is on record: without this the one-per-receiver policy never refuses
    /// anything, and an option that cannot fire is a promise the deployment cannot keep.
    /// </remarks>
    public async Task<bool> LosesToAnotherAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken)
    {
        if (options.AllowMultipleStreamsPerReceiver)
        {
            return false;
        }

        var streams = await store.ListAsync(receiverId, cancellationToken);

        // The lowest identifier stays, whoever asked first. A rule both racers can evaluate
        // the same way is what keeps them from both withdrawing and leaving the receiver with
        // no stream at all.
        return streams.Count > 1
               && streams.Select(existing => existing.StreamId).Order(StringComparer.Ordinal).First() != streamId;
    }
}
