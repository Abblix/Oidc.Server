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
