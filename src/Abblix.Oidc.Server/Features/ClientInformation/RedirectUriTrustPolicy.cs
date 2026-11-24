// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Trusts the redirect URIs of a client somebody answering for the deployment let in, and of no other, as the
/// client's record says: <see cref="ClientInfo.Trust"/>, decided when the client was created. RFC 9700 section 4.11.2
/// names "the source of the redirection URI and other client data" among what the decision takes into account.
/// </summary>
/// <remarks>
/// It reads the record alone, never the settings the server runs with now, so every replica serving a client from a
/// shared store gives the same answer, and a later change of the settings leaves the clients created before it as
/// they were. A host deciding otherwise writes the client's <see cref="ClientInfo.Trust"/> to its store, or registers
/// its own <see cref="IRedirectUriTrustPolicy"/>.
/// </remarks>
public sealed class RedirectUriTrustPolicy : IRedirectUriTrustPolicy
{
    /// <inheritdoc />
    public Task<bool> IsTrustedAsync(TenantDefinition tenant, ClientInfo client) => Task.FromResult(client.Trust switch
    {
        ClientTrust.Reviewed => true,
        ClientTrust.Unreviewed => false,
        _ => throw new ArgumentOutOfRangeException(nameof(client), client.Trust, "The client's trust is not one known"),
    });
}
