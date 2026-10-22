// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// A tenant's part of the stream store that deletes a stream it created once the creation of the tenant it belongs to
/// turns out to be released.
/// </summary>
/// <remarks>
/// The release is canceled before the tenant's streams are listed and deleted, so a create the store acknowledged
/// before the cancel is in that listing, and one acknowledged after it is removed here; no lock is held across the
/// store's calls. This holds for a store whose listing returns every write it has acknowledged.
/// </remarks>
/// <param name="logger">Records a stream left behind because its deletion failed.</param>
/// <param name="inner">The tenant's part of the store.</param>
/// <param name="released">Canceled once the creation of the tenant is released.</param>
/// <param name="tenantId">The tenant and creation the part belongs to, as a stream left behind is logged with.</param>
internal sealed partial class ReleaseCheckingStreamStore(
    ILogger logger,
    IStreamStore inner,
    CancellationToken released,
    string tenantId) : ForwardingStreamStore(inner)
{
    /// <inheritdoc />
    public override async Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        var created = await Inner.TryCreateAsync(stream, cancellationToken);
        if (!created || !released.IsCancellationRequested)
            return created;

        // Deleted whatever the caller's token says: a caller giving up must not leave the stream for nobody to delete
        try
        {
            await Inner.DeleteAsync(stream.ReceiverId, stream.Configuration.StreamId, CancellationToken.None);
        }
        catch (Exception exception)
        {
            LogReleasedStreamNotDeleted(exception, stream.ReceiverId, stream.Configuration.StreamId, tenantId);
            throw;
        }

        return created;
    }
}
