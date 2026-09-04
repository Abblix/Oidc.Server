// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The bundle of controls a <see cref="ClientSecurityProfile"/> forces on a client, expressed as
/// individual flags the request-pipeline validators consult. This is the single place the
/// profile-to-controls mapping lives, so a validator never needs to know what "FAPI 2.0" means - it
/// only reads the one flag it owns - and adding a future profile touches only <see cref="Resolve(ClientSecurityProfile)"/>.
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
/// removes, which <see cref="FindUnreplacedRelaxations()"/> checks for every profile at startup rather
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
    /// (RFC 9449) or a certificate-bound token over mutual TLS (RFC 8705 section 3). Enforced by
    /// <c>Endpoints.Token.Validation.DPoPTokenEndpointValidator</c>.
    /// </summary>
    public bool RequireSenderConstrainedTokens { get; init; }

    /// <summary>
    /// The furthest either clock window may reach under this profile, or null where the profile
    /// puts no bound on them. Read by every place that builds JWT validation parameters.
    /// </summary>
    /// <remarks>
    /// Unlike the flags around it this carries a VALUE, because the requirement names one and a
    /// boolean would leave each reader to remember it - which is how two readers come to bound
    /// the same thing differently. Null rather than a large number, so that a profile putting no
    /// bound on the future is the ABSENCE of one and cannot be mistaken for a generous bound
    /// somebody chose.
    /// </remarks>
    public TimeSpan? MaxClockSkew { get; init; }

    /// <summary>
    /// The tolerance in force where a deployment names none of its own - an answer this profile
    /// supplies rather than imposes: a deployment setting a value of its own wins over it, and is
    /// held only by <see cref="MaxClockSkew"/>.
    /// </summary>
    /// <remarks>
    /// Selecting no profile is a posture rather than the absence of one, and its answer is
    /// <see cref="UnprofiledClockSkew"/>: an assertion arrives from an issuer whose clock this
    /// server does not run, and RFC 7523 Section 3 allows for that offset without naming a bound.
    ///
    /// Where a profile bounds freshness the two halves part company: an expiry the client itself
    /// chose is a deadline this server has no reason to extend, because the grace exists for a clock
    /// that disagrees rather than for a token that is simply late.
    /// </remarks>
    public ClockSkew DefaultClockSkew { get; init; } = UnprofiledClockSkew;

    /// <summary>
    /// What a deployment held to no bounding profile grants either way.
    /// </summary>
    /// <remarks>
    /// Generous because the clock it is measured against belongs to somebody else: an issuer this
    /// server trusts but does not run. A profile that cares about freshness names its own window;
    /// this is what is left when none does.
    /// </remarks>
    private static readonly ClockSkew UnprofiledClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The tolerance that actually applies: what the caller configured where it configured
    /// anything, otherwise <see cref="DefaultClockSkew"/>, in either case held to
    /// <see cref="MaxClockSkew"/>.
    /// </summary>
    /// <remarks>
    /// The bound is applied HERE rather than carried onward beside the value, so that no reader can
    /// take one without the other. A ceiling travelling as a second field is a ceiling somebody
    /// forgets to pass, and the omission reads as a deployment allowed to be looser rather than as
    /// the mistake it is.
    /// </remarks>
    /// <param name="configured">A tolerance the caller set, or null to take this profile's own.</param>
    public ClockSkew ClockSkewOrDefault(ClockSkew? configured = null)
        => (configured ?? DefaultClockSkew).BoundedBy(MaxClockSkew);

    /// <summary>
    /// The profile permits only the authorization-code response type, rejecting any implicit or
    /// hybrid response type that returns a token or id_token from the authorization endpoint.
    /// Enforced by <c>Endpoints.Authorization.Validation.FlowTypeValidator</c> at request time and
    /// by <see cref="SecurityProfileConsistency"/> as a fail-loud registration/startup check.
    /// </summary>
    public bool RequireCodeResponseTypeOnly { get; init; }

    /// <summary>
    /// The profile requires strict RFC 9101 section 6.3 request-object processing: only the parameters inside the
    /// request object are used and any parameter passed outside it is ignored, instead of the OpenID Connect
    /// Core section 6.1 merge behaviour. FAPI 2.0 mandates JWT-Secured Authorization Requests with this exclusivity.
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
    /// <c>Features.ClientAuthentication.JwtAssertionAuthenticatorBase</c>.
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

        MaxClockSkew = ClockSkew.Fapi2Ceiling,

        DefaultClockSkew = ClockSkew.Fapi2,

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
        => FindUnreplacedRelaxations(
            Enum.GetValues<ClientSecurityProfile>()
                .Select(profile => (profile.ToString(), Resolve(profile))));

    /// <summary>
    /// The walk itself, over named bundles supplied by the caller. Separate from the overload above
    /// so a test can drive the mistake this guard exists to catch: a profile that forbids rotation
    /// and carries neither replacement cannot be expressed by the profiles that ship, because they
    /// are correct, and a guard nothing can make fail is not a guard.
    /// </summary>
    internal static IReadOnlyList<string> FindUnreplacedRelaxations(
        IEnumerable<(string Name, SecurityProfileRequirements Requirements)> profiles)
    {
        var violations = new List<string>();

        foreach (var (profile, requirements) in profiles)
        {
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
    /// <remarks>
    /// The default arm throws rather than answering <see cref="NoneRequirements"/>. A profile added
    /// to the enum without a bundle here would otherwise resolve to no requirements at all, which
    /// is silently the weakest answer available and reads at every call site as a deliberate one.
    ///
    /// A value the enum does not define is a different population and gets a different answer. It
    /// arrives from outside - a configuration binder takes a number outside the range as it stands,
    /// and a client store the host writes can hold anything - so it is data rather than a mistake in
    /// this file, and the readers meeting it are handling a live request. Throwing there turns a
    /// host's bad value into a 500 from the authorization and token endpoints, which is the reader's
    /// failure rather than the writer's. It resolves to <see cref="StrictestRequirements"/> instead:
    /// nothing here can say what the value meant, and of the answers available only the strictest
    /// cannot quietly serve a client the deployment believed was constrained.
    /// </remarks>
    public static SecurityProfileRequirements Resolve(ClientSecurityProfile profile)
        => Resolve(profile, Declared(profile));

    /// <summary>
    /// The decision the overload above makes, over a bundle supplied by the caller. Separate so a
    /// test can hand a DEFINED profile no bundle, which is the only way to reach the refusal below:
    /// every profile that ships has one, so the arm would otherwise be dead under test and could be
    /// deleted with the suite staying green - the same reason
    /// <see cref="FindUnreplacedRelaxations()"/> carries its own overload.
    /// </summary>
    internal static SecurityProfileRequirements Resolve(
        ClientSecurityProfile profile,
        SecurityProfileRequirements? declared)
    {
        if (declared != null)
            return declared;

        if (!Enum.IsDefined(profile))
            return StrictestRequirements;

        throw new InvalidOperationException(
            $"{nameof(ClientSecurityProfile)}.{profile} has no requirements declared in " +
            $"{nameof(SecurityProfileRequirements)}");
    }

    /// <summary>
    /// The bundle written for a profile in this file, or null where none is - which is a question
    /// about this file alone, with no judgement about what an absent one means.
    /// </summary>
    private static SecurityProfileRequirements? Declared(ClientSecurityProfile profile) => profile switch
    {
        ClientSecurityProfile.None => NoneRequirements,
        ClientSecurityProfile.Fapi2 => Fapi2Requirements,
        _ => null,
    };

    /// <summary>
    /// The answer for a profile value nothing here can interpret: every control this type can demand,
    /// demanded.
    /// </summary>
    /// <remarks>
    /// Deliberately not <see cref="Fapi2Requirements"/>, which would tie the fallback to whichever
    /// profile happens to be strictest today, and deliberately not <see cref="NoneRequirements"/>,
    /// which would hand a client that named a profile the absence of one.
    ///
    /// <see cref="ForbidRefreshTokenRotation"/> stays false here, and that is the strict setting
    /// rather than an omission: it is the one flag on this type that REMOVES a control, so demanding
    /// it would weaken the bundle meant to be the strongest available.
    ///
    /// Internal rather than private so a test can assert the property this bundle claims - every
    /// tightening flag set - rather than the list somebody remembered to write. A flag added to this
    /// type and forgotten here would otherwise leave the strictest answer quietly short of one
    /// control, which is exactly the outcome it exists to prevent.
    /// </remarks>
    internal static readonly SecurityProfileRequirements StrictestRequirements = new()
    {
        RequirePkce = true,
        RequireS256CodeChallenge = true,
        RequirePushedAuthorizationRequests = true,
        RequireSenderConstrainedTokens = true,

        MaxClockSkew = ClockSkew.Fapi2Ceiling,
        DefaultClockSkew = ClockSkew.Fapi2,
        RequireCodeResponseTypeOnly = true,
        RequireStrictRequestObjectProcessing = true,
        RequireConfidentialClient = true,
        RequireKeyBasedClientAuthentication = true,
        RequireIssuerAudienceInClientAssertion = true,
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
