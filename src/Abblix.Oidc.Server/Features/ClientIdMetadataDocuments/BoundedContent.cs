// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// Reads a response body no further than a limit.
/// </summary>
internal static class BoundedContent
{
    /// <summary>
    /// The response body, or null when it holds more than <paramref name="limit"/> bytes.
    /// </summary>
    /// <remarks>
    /// Section 10.11 has the server stop "after a maximum number of bytes and treating the response as an error if
    /// that limit is reached before the document has been fully read", so the body is read up to one byte past the
    /// limit whatever its Content-Length says, and a declared length past it is refused without reading.
    /// </remarks>
    public static async Task<byte[]?> ReadAsync(HttpContent content, int limit, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > limit)
            return null;

        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[limit + 1];
        var length = 0;
        int read;
        while (length < buffer.Length &&
               (read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken)) > 0)
        {
            length += read;
        }

        return length > limit ? null : buffer[..length];
    }
}
