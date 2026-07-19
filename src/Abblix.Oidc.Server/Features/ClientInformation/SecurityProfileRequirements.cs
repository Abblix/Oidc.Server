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

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The bundle of controls a <see cref="ClientSecurityProfile"/> forces on a client, expressed as
/// individual flags the request-pipeline validators consult. This is the single place the
/// profile-to-controls mapping lives, so a validator never needs to know what "FAPI 2.0" means — it
/// only reads the one flag it owns — and adding a future profile touches only <see cref="Resolve"/>.
/// </summary>
/// <remarks>
/// Each flag is enforcement-only: it can require a control but never relax one. A profile therefore
/// tightens a client and cannot weaken it, which is the invariant that lets a granular toggle (for
/// example <see cref="ClientInfo.PkceRequired"/> set to <c>false</c>) coexist with a profile without
/// silently downgrading it.
///
/// Every flag below names the validator that enforces it. That coupling is documented here on
/// purpose: the enforcement is distributed across the request pipeline, so a new flag added to a
/// profile without a matching consumer would ship silently unenforced. When adding a flag, wire a
/// validator that reads it and a test that proves the control fires.
/// </remarks>
public sealed record SecurityProfileRequirements
{
    /// <summary>
    /// The profile mandates PKCE on every authorization request, even when the client's own
    /// <see cref="ClientInfo.PkceRequired"/> is <c>false</c>. Enforced by
    /// <c>Endpoints.Authorization.Validation.PkceValidator</c>.
    /// </summary>
    public bool RequirePkce { get; init; }

    /// <summary>
    /// The profile restricts the PKCE code challenge method to exactly <c>S256</c>, rejecting both
    /// <c>plain</c> and the non-standard <c>S512</c> extension. FAPI 2.0 names <c>S256</c>, and the
    /// IANA "PKCE Code Challenge Methods" registry defines only <c>plain</c> and <c>S256</c>, so a
    /// conformance suite never presents <c>S512</c>. Enforced by
    /// <c>Endpoints.Authorization.Validation.PkceValidator</c>.
    /// </summary>
    public bool RequireS256CodeChallenge { get; init; }

    /// <summary>
    /// The profile requires the client to start every authorization flow through a Pushed
    /// Authorization Request, independent of the server-wide
    /// <see cref="Common.Configuration.OidcOptions.RequirePushedAuthorizationRequests"/> flag.
    /// Enforced by <c>Endpoints.Authorization.RequestFetching.PushedRequestFetcher</c>.
    /// </summary>
    public bool RequirePushedAuthorizationRequests { get; init; }

    /// <summary>
    /// The profile requires a sender-constrained access token, satisfied by either a DPoP proof
    /// (RFC 9449) or a certificate-bound token over mutual TLS (RFC 8705 §3). Enforced by
    /// <c>Endpoints.Token.Validation.DPoPTokenEndpointValidator</c>.
    /// </summary>
    public bool RequireSenderConstrainedTokens { get; init; }

    /// <summary>
    /// The profile permits only the authorization-code response type, rejecting any implicit or
    /// hybrid response type that returns a token or id_token from the authorization endpoint.
    /// Enforced by <c>Endpoints.Authorization.Validation.FlowTypeValidator</c> at request time and
    /// by <see cref="SecurityProfileConsistency"/> as a fail-loud registration/startup check.
    /// </summary>
    public bool RequireCodeResponseTypeOnly { get; init; }

    /// <summary>
    /// The profile requires strict RFC 9101 §6.3 request-object processing: only the parameters inside the
    /// request object are used and any parameter passed outside it is ignored, instead of the OpenID Connect
    /// Core §6.1 merge behaviour. FAPI 2.0 mandates JWT-Secured Authorization Requests with this exclusivity.
    /// Enforced by <c>Features.RequestObject.RequestObjectFetcher</c>.
    /// </summary>
    public bool RequireStrictRequestObjectProcessing { get; init; }

    private static readonly SecurityProfileRequirements NoneRequirements = new();

    private static readonly SecurityProfileRequirements Fapi2Requirements = new()
    {
        RequirePkce = true,
        RequireS256CodeChallenge = true,
        RequirePushedAuthorizationRequests = true,
        RequireSenderConstrainedTokens = true,
        RequireCodeResponseTypeOnly = true,
        RequireStrictRequestObjectProcessing = true,
    };

    /// <summary>
    /// Returns the control bundle a given profile mandates.
    /// </summary>
    public static SecurityProfileRequirements Resolve(ClientSecurityProfile profile) => profile switch
    {
        ClientSecurityProfile.Fapi2 => Fapi2Requirements,
        _ => NoneRequirements,
    };

    /// <summary>
    /// Resolves the profile that actually governs a client: the client's own
    /// <see cref="ClientInfo.SecurityProfile"/> when it states one (including an explicit
    /// <see cref="ClientSecurityProfile.None"/> opt-out), otherwise the server-wide default. A client
    /// therefore opts in or out individually, while a single-profile deployment sets the default once
    /// and every unprofiled client inherits it.
    /// </summary>
    /// <param name="clientProfile">The profile stated on the client, or <c>null</c> when unset.</param>
    /// <param name="defaultProfile">The server-wide default profile to fall back to.</param>
    public static ClientSecurityProfile Effective(
        ClientSecurityProfile? clientProfile,
        ClientSecurityProfile defaultProfile)
        => clientProfile ?? defaultProfile;

    /// <summary>
    /// Convenience entry point for the validators: resolves the effective profile for a client and
    /// returns its control bundle in one call.
    /// </summary>
    /// <param name="client">The client whose effective profile is being resolved.</param>
    /// <param name="defaultProfile">The server-wide default profile to fall back to.</param>
    public static SecurityProfileRequirements For(ClientInfo client, ClientSecurityProfile defaultProfile)
        => Resolve(Effective(client.SecurityProfile, defaultProfile));
}
