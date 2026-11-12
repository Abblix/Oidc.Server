// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant declaring a client whose assertion audiences lack the issuer identifier or name a value the
/// enumeration does not define.
/// </summary>
/// <remarks>
/// RFC 10070 section 4 holds every client to the issuer identifier, and the other values only widen what it may write
/// beside that. A set without the issuer would refuse every assertion a conforming client sends, and configuration
/// binds a number to an enumeration whatever its value, so either would otherwise let the host start and fail each
/// authentication of that client, a refusal seen only in the log. A value left at zero reads as the issuer alone and
/// passes.
/// </remarks>
public sealed class ClientAssertionAudiencesCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, tenant => Failures(tenant.Clients));

    private static IEnumerable<string> Failures(IEnumerable<ClientInfo> clients)
        => clients
            .Where(client => !IsAccepted(client.ClientAssertionAudiences))
            .Select(client =>
                $"The client '{client.ClientId}' is configured with {nameof(ClientInfo.ClientAssertionAudiences)} " +
                $"'{client.ClientAssertionAudiences}', which is not a set this server accepts: it holds " +
                $"{nameof(ClientAssertionAudiences.Issuer)} and may add " +
                $"{nameof(ClientAssertionAudiences.TokenEndpoint)} and {nameof(ClientAssertionAudiences.AllowArray)}.");

    /// <summary>
    /// Whether <paramref name="audiences"/> is a set the server applies: the issuer identifier, alone or with the
    /// values that widen it, and nothing the enumeration does not define.
    /// </summary>
    internal static bool IsAccepted(ClientAssertionAudiences audiences)
    {
        switch (audiences)
        {
            case ClientAssertionAudiences.Issuer:
            case ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint:
            case ClientAssertionAudiences.Issuer | ClientAssertionAudiences.AllowArray:
            case ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint |
                 ClientAssertionAudiences.AllowArray:
                return true;

            default:
                return false;
        }
    }
}
