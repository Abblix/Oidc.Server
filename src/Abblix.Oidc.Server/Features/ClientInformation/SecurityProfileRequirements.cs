// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The bundle of controls a <see cref="ClientSecurityProfile"/> forces on a client, expressed as
/// individual flags the request-pipeline validators consult. This is the single place the
/// profile-to-controls mapping lives, so a validator never needs to know what "FAPI 2.0" means - it
/// only reads the one flag it owns - and adding a future profile touches only <see cref="Resolve"/>.
/// </summary>
/// <remarks>
/// A flag normally requires a control and never relaxes one, so a profile tightens a client and
/// cannot weaken it. That is what lets a granular toggle (for example
/// <see cref="ClientInfo.PkceRequired"/> set to <c>false</c>) coexist with a profile without silently
/// downgrading it.
///
/// One flag goes the other way, and the exception is deliberate rather than an escape hatch.
/// <see cref="ForbidRefreshTokenRotation"/> removes a control, because the specification it comes
/// from replaces that control with two others instead of dropping protection: rotation earns nothing
/// once the client is confidential and its tokens are bound to their sender, and it costs a user
/// their session whenever a client fails to store the token it was handed. A relaxing flag is
/// therefore admissible only when the same profile carries the controls that stand in for what it
/// removes, which <see cref="FindUnreplacedRelaxations"/> checks for every profile at startup rather
/// than leaving to review.
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

    /// <summary>
    /// The profile admits only confidential clients as defined by RFC 6749, so a client that
    /// authenticates with nothing at the token endpoint cannot be held to it. Enforced by
    /// <see cref="SecurityProfileConsistency"/> at registration and at startup.
    /// </summary>
    public bool RequireConfidentialClient { get; init; }

    /// <summary>
    /// The profile admits only client authentication that proves possession of a key: mutual TLS
    /// (RFC 8705 section 2) or a private key JWT assertion (OpenID Connect Core section 9). Every
    /// method keyed on a shared secret is refused. Enforced by
    /// <see cref="SecurityProfileConsistency"/> at registration and at startup.
    /// </summary>
    public bool RequireKeyBasedClientAuthentication { get; init; }

    /// <summary>
    /// The profile accepts only the server's issuer identifier, and only as a string, in the
    /// audience of a client authentication assertion, narrowing what the underlying specification
    /// otherwise permits. Enforced by
    /// <c>Features.ClientAuthentication.ClientAssertionAudienceValidator</c>.
    /// </summary>
    public bool RequireIssuerAudienceInClientAssertion { get; init; }

    /// <summary>
    /// The profile forbids refresh token rotation, which is the one flag that removes a control
    /// rather than requiring one. See the remarks on this type for why that is admissible here and
    /// what stands in its place. Enforced by
    /// <c>Features.Tokens.RefreshTokenService</c>.
    /// </summary>
    public bool ForbidRefreshTokenRotation { get; init; }

    private static readonly SecurityProfileRequirements NoneRequirements = new();

    private static readonly SecurityProfileRequirements Fapi2Requirements = new()
    {
        RequirePkce = true,
        RequireS256CodeChallenge = true,
        RequirePushedAuthorizationRequests = true,
        RequireSenderConstrainedTokens = true,
        RequireCodeResponseTypeOnly = true,
        RequireStrictRequestObjectProcessing = true,
        RequireConfidentialClient = true,
        RequireKeyBasedClientAuthentication = true,
        RequireIssuerAudienceInClientAssertion = true,
        ForbidRefreshTokenRotation = true,
    };

    /// <summary>
    /// Names every profile that removes a control without carrying the controls that stand in for
    /// it. An empty list means each relaxation in this file is paid for.
    /// </summary>
    /// <remarks>
    /// This exists because a relaxing flag is one edit away from becoming an ordinary permission.
    /// Someone adding a profile, or loosening an existing one, sees a set of booleans with no
    /// direction to them, and nothing in the type distinguishes the flag that removes protection
    /// from the nine that add it. So the condition that makes the removal sound is stated as code
    /// and run at startup, where it can fail, rather than as a paragraph that can be skipped.
    ///
    /// Refusing refresh token rotation is sound only alongside a confidential client and a
    /// sender-constrained token, because those two are what make rotation redundant. A profile
    /// carrying the relaxation without them would hand out long-lived multi-use refresh tokens to a
    /// client that may be public and whose tokens anyone may replay.
    /// </remarks>
    public static IReadOnlyList<string> FindUnreplacedRelaxations()
    {
        var violations = new List<string>();

        foreach (var profile in Enum.GetValues<ClientSecurityProfile>())
        {
            var requirements = Resolve(profile);
            if (!requirements.ForbidRefreshTokenRotation)
                continue;

            if (!requirements.RequireConfidentialClient)
            {
                violations.Add(
                    $"the {profile} profile forbids refresh token rotation without requiring a " +
                    "confidential client, which is one of the two controls that replace it");
            }

            if (!requirements.RequireSenderConstrainedTokens)
            {
                violations.Add(
                    $"the {profile} profile forbids refresh token rotation without requiring a " +
                    "sender-constrained token, which is one of the two controls that replace it");
            }
        }

        return violations;
    }

    /// <summary>
    /// Returns the control bundle a given profile mandates.
    /// </summary>
    public static SecurityProfileRequirements Resolve(ClientSecurityProfile profile) => profile switch
    {
        ClientSecurityProfile.Fapi2 => Fapi2Requirements,
        _ => NoneRequirements,
    };

    /// <summary>
    /// Convenience entry point for the validators: resolves the effective profile for a client and
    /// returns its control bundle in one call.
    /// </summary>
    /// <param name="client">The client whose effective profile is being resolved.</param>
    /// <param name="defaultProfile">The server-wide default profile to fall back to.</param>
    public static SecurityProfileRequirements For(ClientInfo client, ClientSecurityProfile defaultProfile)
        => Resolve(client.SecurityProfile ?? defaultProfile);
}
