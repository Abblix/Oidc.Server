// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// The names of the clients registered with SSRF address validation, recorded as they are registered.
/// </summary>
/// <remarks>
/// The registration is the only place that knows which clients these are, so it writes the name down rather than
/// leaving anything downstream to infer it from a list that would drift as clients are added.
/// </remarks>
internal sealed class SsrfGuardedClients
{
    private readonly HashSet<string> _names = new(StringComparer.Ordinal);

    /// <summary>Records a client as one whose primary handler carries the address validation.</summary>
    /// <param name="name">The client's logical name, as <c>IHttpClientFactory</c> keys it.</param>
    public void Add(string name) => _names.Add(name);

    /// <summary>Tells whether a client was registered with the validation.</summary>
    /// <param name="name">The client's logical name.</param>
    public bool Contains(string name) => _names.Contains(name);
}
