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

using System.Net.Http.Json;
using System.Net.Mime;
using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Receiver;

/// <summary>
/// Fetches a transmitter's configuration metadata from the well-known address its issuer
/// identifier resolves to (SSF 1.0 Sections 7.2, 7.2.1), and refuses a document that does not
/// assert the issuer it was fetched for.
/// </summary>
/// <remarks>
/// Authentication, proxies and retries are the <see cref="HttpClient"/>'s configuration - the
/// host wires them where it wires every other outbound client; this type owns only the SSF
/// mechanics.
/// </remarks>
/// <param name="httpClient">The client the document is fetched with.</param>
public sealed class TransmitterConfigurationClient(HttpClient httpClient)
{
    /// <summary>
    /// Fetches the Transmitter Configuration Metadata for <paramref name="issuer"/>.
    /// </summary>
    /// <param name="issuer">The transmitter's issuer identifier, from a trusted source
    /// (SSF 1.0 Section 7.2).</param>
    /// <param name="cancellationToken">Cancels the fetch.</param>
    /// <returns>The metadata document, its issuer identity confirmed.</returns>
    /// <exception cref="HttpRequestException">The transmitter answered with an error status.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The document is empty, or asserts an issuer other than the one it was fetched for - the
    /// SSF counterpart of the identity check every discovery protocol makes, without which a
    /// document served on one issuer's path could impersonate another issuer of the same host.
    /// </exception>
    public async Task<TransmitterConfiguration> GetAsync(
        Uri issuer,
        CancellationToken cancellationToken = default)
    {
        var address = TransmitterConfiguration.WellKnownAddress(issuer);

        using var response = await httpClient.GetAsync(address, cancellationToken);
        response.EnsureSuccessStatusCode();

        // Section 7.2 requires the document be returned as "application/json", and the check is
        // real work this side must do - the deserializer parses whatever bytes it is handed, so
        // without it a captive portal's page that happens to parse would be accepted as the
        // transmitter's word.
        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (!string.Equals(mediaType, MediaTypeNames.Application.Json, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The document at '{address}' arrived as '{mediaType ?? "(no content type)"}', where "
                + "SSF 1.0 Section 7.2 requires \"application/json\".");
        }

        var metadata = await response.Content.ReadFromJsonAsync<TransmitterConfiguration>(cancellationToken)
            ?? throw new InvalidOperationException(
                $"The transmitter configuration document at '{address}' deserialized to null.");

        // Compared as normalized absolute URIs, not with Uri.Equals: Uri equality disregards
        // userinfo and fragment, so "https://evil@tr.example.com" would pass for
        // "https://tr.example.com". AbsoluteUri keeps every component while still folding the
        // one artifact worth folding - a root issuer and its slash-terminated spelling are one
        // identity.
        if (!Uri.TryCreate(metadata.Issuer, UriKind.Absolute, out var declaredIssuer)
            || !string.Equals(declaredIssuer.AbsoluteUri, issuer.AbsoluteUri, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The document at '{address}' asserts the issuer '{metadata.Issuer}', not the "
                + $"'{issuer}' it was fetched for; accepting it would let one issuer of a host "
                + "answer for another (SSF 1.0 Sections 7.1, 7.2).");
        }

        return metadata;
    }
}
