// Abblix OIDC Client Library
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

using Abblix.Oidc.Client.Features.Discovery;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.FrontChannelLogout;

/// <summary>
/// Reads a front-channel logout request and says what it is about.
/// </summary>
/// <param name="metadataProvider">Supplies the issuer this client is talking to.</param>
/// <param name="options">What this client requires of such a request.</param>
public sealed class FrontChannelLogoutRequestReader(
    IProviderMetadataProvider metadataProvider,
    IOptions<FrontChannelLogoutOptions> options) : IFrontChannelLogoutRequestReader
{
    /// <inheritdoc />
    public async Task<FrontChannelLogoutNotification> ReadAsync(
        IReadOnlyDictionary<string, string?> parameters, CancellationToken cancellationToken = default)
    {
        parameters.TryGetValue(Parameters.Issuer, out var issuer);
        parameters.TryGetValue(Parameters.SessionId, out var sessionId);

        issuer = Trimmed(issuer);
        sessionId = Trimmed(sessionId);

        // Section 2: "The OP MAY add these query parameters when rendering the logout URI, and if either is
        // included, both MUST be." One without the other is a request no provider was allowed to send, and
        // reading it as a partial answer would mean guessing which half was meant.
        if (issuer is null != sessionId is null)
        {
            throw new FrontChannelLogoutException(
                "A front-channel logout request naming one of iss and sid must name both.");
        }

        if (options.Value.SessionRequired && issuer is null)
        {
            throw new FrontChannelLogoutException(
                $"{nameof(FrontChannelLogoutOptions)}.{nameof(FrontChannelLogoutOptions.SessionRequired)} "
                + "is set, so a front-channel logout request must name the issuer and the session. Register "
                + "frontchannel_logout_session_required with the provider as well, or this client refuses "
                + "every logout it sends.");
        }

        if (issuer is not null)
            await RequireOurIssuerAsync(issuer, cancellationToken);

        return new FrontChannelLogoutNotification(issuer, sessionId);
    }

    /// <summary>
    /// Refuses a request naming a provider this client does not use.
    /// </summary>
    /// <remarks>
    /// Ours, not a clause from the specification. It buys little against an attacker - the endpoint takes no
    /// token, so anyone who can reach it can trigger a logout whatever they put in the query - and that is
    /// not what it is for. It is so that an identifier this client never checked is not handed on as though
    /// it were the provider's own, to be compared against sessions by a host that has no way of knowing it
    /// arrived unverified.
    /// </remarks>
    private async Task RequireOurIssuerAsync(string issuer, CancellationToken cancellationToken)
    {
        var metadata = await metadataProvider.GetMetadataAsync(cancellationToken);

        if (!string.Equals(issuer, metadata.Issuer, StringComparison.Ordinal))
        {
            throw new FrontChannelLogoutException(
                $"The front-channel logout request names issuer '{issuer}', which is not the provider this "
                + "client uses.");
        }
    }

    /// <summary>
    /// Treats a parameter present but empty as absent, since an empty issuer or session identifies nothing.
    /// </summary>
    private static string? Trimmed(string? value) => string.IsNullOrEmpty(value) ? null : value;
}
