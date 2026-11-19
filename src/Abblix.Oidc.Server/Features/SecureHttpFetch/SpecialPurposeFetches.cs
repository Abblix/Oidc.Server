// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Marks the fetches made for a client resolved from its metadata document, which the SSRF validation holds to the
/// special-purpose address registries as written.
/// </summary>
/// <remarks>
/// Draft-ietf-oauth-client-id-metadata-document section 10.7: the server "MUST NOT fetch a Client ID Metadata Document
/// URL or any URLs contained within a Client ID Metadata Document that resolve to special-use IP addresses as defined
/// in [RFC6890]". The validation every other fetch passes lets the NAT64 prefix reach the public IPv4 address it
/// carries, which an IPv6-only network needs; a fetch made inside a scope opened here refuses it. The scope flows with
/// the call into the handler that resolves the name, so the rule is decided where the address is known.
/// </remarks>
internal static class SpecialPurposeFetches
{
    private static readonly AsyncLocal<bool> Strict = new();

    /// <summary>
    /// Whether the fetch being made is one for a client resolved from its metadata document.
    /// </summary>
    public static bool Active => Strict.Value;

    /// <summary>
    /// Opens a scope whose fetches refuse every special-purpose address, until it is disposed.
    /// </summary>
    public static IDisposable Enter()
    {
        var previous = Strict.Value;
        Strict.Value = true;
        return new Scope(previous);
    }

    /// <summary>
    /// Opens such a scope for the fetches made on behalf of <paramref name="client"/> when it was resolved from its
    /// metadata document, and none otherwise.
    /// </summary>
    public static IDisposable? For(ClientInfo client) => client.ResolvedFromMetadataDocument ? Enter() : null;

    private sealed class Scope(bool previous) : IDisposable
    {
        public void Dispose() => Strict.Value = previous;
    }
}
