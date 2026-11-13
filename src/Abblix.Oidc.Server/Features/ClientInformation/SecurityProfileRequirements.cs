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
    /// The profile requires a pushed authorization request to carry a PKCE code challenge with the <c>S256</c> method,
    /// whether or not it requires PKCE of a request sent to the authorization endpoint directly. FAPI 1.0 Part 2
    /// section 5.2.2: the server "shall require PAR requests, if supported, to use PKCE (RFC7636) with S256 as the code
    /// challenge method". Enforced by <c>Endpoints.PushedAuthorization.PushedAuthorizationRequestValidator</c>.
    /// </summary>
    public bool RequirePkceWithPushedRequests { get; init; }

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
    /// <c>Endpoints.Token.Validation.DPoPBindingValidator</c>.
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
    /// take one without the other. A ceiling traveling as a second field is a ceiling somebody
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
    /// The profile requires every redirect URI to use the https scheme and the one a request names to match a registered
    /// one exactly, without the loopback port allowance of RFC 8252 section 7.3. FAPI 1.0 Part 1 section 5.2.2, which
    /// Part 2 section 5.2.2 takes in: the server "shall require the value of redirect_uri to exactly match one of the
    /// pre-registered redirect URIs" and "shall require redirect URIs to use the https scheme". Enforced by
    /// <c>Endpoints.Authorization.Validation.RedirectUriValidator</c> at request time and by
    /// <see cref="SecurityProfileConsistency"/> at registration and at startup.
    /// </summary>
    public bool RequireExactHttpsRedirectUris { get; init; }

    /// <summary>
    /// The profile requires a client publishing its keys at a jwks_uri to serve it over TLS. FAPI 1.0 Part 2 section
    /// 8.9: "this profile ... requires that jwks_uri endpoints shall be served over TLS". Held by
    /// <see cref="SecurityProfileConsistency"/> at registration, at startup and where the client authenticates, whatever
    /// schemes the host lets the outbound fetcher use.
    /// </summary>
    public bool RequireHttpsJwksUri { get; init; }

    /// <summary>
    /// The profile admits only an authorization response the server signs: the response type <c>code id_token</c>,
    /// whose ID token is the response's detached signature, or the response type <c>code</c> with the response mode
    /// <c>jwt</c> (JARM). FAPI 1.0 Part 2 section 5.2.2 has the server "require the response_type value code
    /// id_token, or the response_type value code in conjunction with the response_mode value jwt". Enforced by
    /// <c>Endpoints.Authorization.Validation.FlowTypeValidator</c>.
    /// </summary>
    /// <remarks>
    /// The response mode is the one the clause names, <c>jwt</c>, and not the other JARM modes: the clause names one
    /// value, and the others are what it leaves out. Held together with <see cref="RequireCodeResponseTypeOnly"/>,
    /// code with the response mode <c>jwt</c> is what both admit.
    /// </remarks>
    public bool RequireSignedAuthorizationResponse { get; init; }

    /// <summary>
    /// The profile requires strict RFC 9101 section 6.3 request-object processing: only the parameters inside the
    /// request object are used and any parameter passed outside it is ignored, instead of the OpenID Connect
    /// Core section 6.1 merge behavior. FAPI 2.0 mandates JWT-Secured Authorization Requests with this exclusivity.
    /// Enforced by <c>Features.RequestObject.RequestObjectFetcher</c>.
    /// </summary>
    public bool RequireStrictRequestObjectProcessing { get; init; }

    /// <summary>
    /// The profile requires every authorization request to arrive as a signed request object, by value or by
    /// reference, as <see cref="ClientInfo.RequireSignedRequestObject"/> does for one client: plain parameters and an
    /// unsigned (<c>none</c>) object are refused. FAPI 1.0 Part 2 section 5.2.2 has the server "require a JWS signed
    /// JWT request object passed by value with the request parameter or by reference with the request_uri
    /// parameter". Enforced by <c>Endpoints.Authorization.Validation.SignedRequestObjectRequirementValidator</c> and
    /// <c>Features.RequestObject.RequestObjectFetcher</c>.
    /// </summary>
    /// <remarks>
    /// Without it strict processing has nothing to apply to: a client sending plain parameters carries no request
    /// object, and every parameter it names is used as sent.
    /// </remarks>
    public bool RequireSignedRequestObject { get; init; }

    /// <summary>
    /// The longest a request object may live under this profile, or null where the profile requires no lifetime
    /// of it. Where set, the request object has to carry both <c>nbf</c> and <c>exp</c>, its <c>exp</c> may lie
    /// no further than this after its <c>nbf</c>, and its <c>nbf</c> no further than this in the past. Enforced by
    /// <c>Features.RequestObject.RequestObjectFetcher</c>.
    /// </summary>
    /// <remarks>
    /// One value for the three demands, because FAPI 2.0 Message Signing section 5.3.1 and FAPI 1.0 Part 2 section
    /// 5.2.2 bound both claims by the same 60 minutes: an nbf "no longer than 60 minutes in the past" and an exp
    /// "no longer than 60 minutes after the nbf claim". A request object signed long ago, or valid for long, is one
    /// whoever obtained it can still present. RFC 9101 alone asks for neither claim, so null is what a deployment
    /// held to no such profile keeps.
    /// </remarks>
    public TimeSpan? MaxRequestObjectLifetime { get; init; }

    /// <summary>
    /// The profile requires a request object to name the issuer identifier as its audience, as a string or inside an
    /// array. FAPI 1.0 Part 2 section 5.2.2 has the server "require the aud claim in the request object to be, or to
    /// be an array containing, the OP's Issuer Identifier URL". Enforced by
    /// <c>Features.RequestObject.RequestObjectFetcher</c>.
    /// </summary>
    /// <remarks>
    /// Narrower than what the server accepts without it: an object naming no audience, or only the endpoint it was
    /// sent to, passes RFC 9101 alone, whose section 4 has the aud claim only SHOULD name the server. The issuer
    /// identifier is the one value that names this server whichever endpoint the object reaches.
    /// </remarks>
    public bool RequireIssuerAudienceInRequestObject { get; init; }

    /// <summary>
    /// The profile requires a nonce on every authorization request naming the <c>openid</c> scope itself, whatever the
    /// response type and whatever default scope it would be served. FAPI 1.0 Part 1 section 5.2.2.2, which Part 2 section 5.2.2 takes in: "If the client requests
    /// the openid scope, the authorization server shall require the nonce parameter". Enforced by
    /// <c>Endpoints.Authorization.Validation.NonceValidator</c>.
    /// </summary>
    /// <remarks>
    /// Wider than OpenID Connect Core, which requires the nonce only where the authorization endpoint returns an ID
    /// token: under this control a code request with the <c>jwt</c> response mode carries one too.
    /// </remarks>
    public bool RequireNonceWithOpenIdScope { get; init; }

    /// <summary>
    /// The profile requires the <c>state</c> parameter on every authorization request not naming the <c>openid</c>
    /// scope. FAPI 1.0 Part 1 section 5.2.2.3, which Part 2 section 5.2.2 takes in: "If the client does not requests
    /// the openid scope, the authorization server shall require the state parameter defined in Section 4.1.1 of
    /// RFC6749". Enforced by <c>Endpoints.Authorization.Validation.StateValidator</c>.
    /// </summary>
    public bool RequireStateWithoutOpenIdScope { get; init; }

    /// <summary>
    /// The profile admits only the PS256 and ES256 signature algorithms, in what the client signs for this server and
    /// in what this server signs for the client. FAPI 1.0 Part 2 section 8.6: "For JWS, both clients and
    /// authorization servers shall use PS256 or ES256 algorithms". Read through <see cref="PermitsSigningAlgorithm"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What the client signs is judged where it is verified: request objects, client authentication assertions and
    /// CIBA login hint tokens in <c>Features.Tokens.Validation.ClientJwtValidator</c>, and JWT bearer grant
    /// assertions in <c>Endpoints.Token.Grants.JwtBearerAssertionPolicy</c>, and DPoP proofs where the client is known:
    /// at the pushed authorization request endpoint and at the token endpoint.
    /// </para>
    /// <para>
    /// What the server signs for the client is judged on the client's configuration, by
    /// <see cref="SecurityProfileConsistency"/> at startup, at registration and where the client authenticates: the
    /// algorithms of its ID tokens, logout tokens and JWT authorization, userinfo and introspection responses. A
    /// registration naming none of the first two is given one a signing key of the tenant produces, by
    /// <c>Endpoints.DynamicClientManagement.Validation.ProfileSigningKeysValidator</c>, and a static client is checked
    /// against the tenant's keys at startup. A client added to the store with others
    /// is refused only where it authenticates, so what the authorization endpoint signs for it before then is what it
    /// was configured with. The tokens this server signs for itself, such as JWT access tokens, take the algorithm
    /// the deployment configures and no client's.
    /// </para>
    /// </remarks>
    public bool RequireFapiSigningAlgorithms { get; init; }

    /// <summary>
    /// The profile forbids the RSA1_5 key management algorithm in what the client encrypts for this server and in what
    /// this server encrypts for the client. FAPI 1.0 Part 2 section 8.6.1: "For JWE, both clients and authorization
    /// servers shall not use the RSA1_5 algorithm". Judged by <c>Features.Tokens.Validation.ClientJwtValidator</c> for
    /// what the client encrypts and by <see cref="SecurityProfileConsistency"/> on the client's configuration.
    /// </summary>
    public bool ForbidRsa1_5KeyManagement { get; init; }

    /// <summary>
    /// Whether a JWE layer encrypted with the key management algorithm <paramref name="algorithm"/> is one this profile
    /// admits.
    /// </summary>
    /// <param name="algorithm">The <c>alg</c> of the JWE's protected header.</param>
    public bool PermitsKeyManagementAlgorithm(string algorithm)
        => !ForbidRsa1_5KeyManagement || algorithm != EncryptionAlgorithms.KeyManagement.Rsa1_5;

    /// <summary>
    /// The signature algorithms <see cref="RequireFapiSigningAlgorithms"/> admits. FAPI 2.0 section 5.4.1 adds EdDSA
    /// with Ed25519, which this library does not implement, so no client of it can use it.
    /// </summary>
    internal static readonly string[] FapiSigningAlgorithms = [SigningAlgorithms.PS256, SigningAlgorithms.ES256];

    /// <summary>
    /// Whether a JWS signed with <paramref name="algorithm"/> is one this profile admits.
    /// </summary>
    /// <param name="algorithm">The <c>alg</c> of the JWS, or null where it names none.</param>
    public bool PermitsSigningAlgorithm(string? algorithm)
        => !RequireFapiSigningAlgorithms || FapiSigningAlgorithms.Contains(algorithm, StringComparer.Ordinal);

    /// <summary>
    /// The request object lifetime the FAPI profiles bound a request object to.
    /// </summary>
    internal static readonly TimeSpan FapiRequestObjectLifetime = TimeSpan.FromMinutes(60);

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
    /// The profile refuses a request naming a client_id other than the client its credential proves. FAPI 1.0 Part 1
    /// section 5.2.2, which Part 2 section 5.2.2 takes in: the server "shall return an invalid_client error as defined
    /// in 5.2 of RFC6749 when mis-matched client identifiers were provided through the client authentication methods
    /// that permits sending the client identifier in more than one way". Enforced by
    /// <c>Features.ClientAuthentication.SecurityProfileClientAuthenticator</c>.
    /// </summary>
    public bool RequireMatchingClientIdentifiers { get; init; }

    /// <summary>
    /// The profile accepts in the audience of a client authentication assertion only the issuer identifier, as a
    /// string, whatever <see cref="ClientInfo.ClientAssertionAudiences"/> the host allows the client: neither the
    /// token endpoint URL nor an array. Enforced by <c>Features.ClientAuthentication.JwtAssertionAuthenticatorBase</c>,
    /// and refused in the client's configuration by <see cref="SecurityProfileConsistency"/>.
    /// </summary>
    public bool RequireStringAudienceInClientAssertion { get; init; }

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

        // FAPI 2.0 Message Signing section 5.3.1, for a request object where one is sent: "shall require the aud
        // claim in the request object to be, or to be an array containing, the authorization server's issuer
        // identifier URL", beside the lifetime the same section bounds
        MaxRequestObjectLifetime = FapiRequestObjectLifetime,
        RequireIssuerAudienceInRequestObject = true,

        RequireConfidentialClient = true,
        RequireKeyBasedClientAuthentication = true,
        RequireStringAudienceInClientAssertion = true,
        ForbidRefreshTokenRotation = true,

        // FAPI 2.0 section 5.4.1: "use PS256, ES256, or EdDSA (using the Ed25519 variant) algorithms"
        RequireFapiSigningAlgorithms = true,
    };

    /// <summary>
    /// FAPI 1.0 Part 2 sections 5.2.2, 8.6, 8.6.1 and 8.9, and the Part 1 section 5.2.2 provisions section 5.2.2 takes
    /// in, the clauses this type has a control for. Each member below names its clause.
    /// </summary>
    /// <remarks>
    /// Left off on purpose, because each would refuse a client that profile admits: the code-only response type
    /// (the section admits <c>code id_token</c> as well), Pushed Authorization Requests (which
    /// it "may support"), PKCE of a request sent directly (it exempts the Baseline clause and asks PKCE with S256 only
    /// of a pushed request, which <see cref="RequirePkceWithPushedRequests"/> holds), and the clock window, assertion
    /// audience and rotation controls, which come from FAPI 2.0 and have no clause in FAPI 1.0.
    /// </remarks>
    private static readonly SecurityProfileRequirements Fapi1AdvancedRequirements = new()
    {
        RequireSenderConstrainedTokens = true,
        RequireStrictRequestObjectProcessing = true,
        RequireSignedRequestObject = true,
        MaxRequestObjectLifetime = FapiRequestObjectLifetime,
        RequireIssuerAudienceInRequestObject = true,
        RequireSignedAuthorizationResponse = true,
        RequireNonceWithOpenIdScope = true,
        RequireStateWithoutOpenIdScope = true,
        RequirePkceWithPushedRequests = true,
        RequireExactHttpsRedirectUris = true,
        RequireHttpsJwksUri = true,
        RequireConfidentialClient = true,
        RequireKeyBasedClientAuthentication = true,
        RequireMatchingClientIdentifiers = true,
        RequireFapiSigningAlgorithms = true,
        ForbidRsa1_5KeyManagement = true,
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
        ClientSecurityProfile.Fapi1Advanced => Fapi1AdvancedRequirements,
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
        RequireSignedAuthorizationResponse = true,
        RequireStrictRequestObjectProcessing = true,
        RequireSignedRequestObject = true,
        MaxRequestObjectLifetime = FapiRequestObjectLifetime,
        RequireIssuerAudienceInRequestObject = true,
        RequireNonceWithOpenIdScope = true,
        RequireStateWithoutOpenIdScope = true,
        RequirePkceWithPushedRequests = true,
        RequireExactHttpsRedirectUris = true,
        RequireHttpsJwksUri = true,
        RequireConfidentialClient = true,
        RequireKeyBasedClientAuthentication = true,
        RequireMatchingClientIdentifiers = true,
        RequireStringAudienceInClientAssertion = true,
        RequireFapiSigningAlgorithms = true,
        ForbidRsa1_5KeyManagement = true,
    };

    /// <summary>
    /// The control bundle a client is actually held to: what the deployment demands of everyone,
    /// tightened by whatever the client names for itself.
    /// </summary>
    /// <remarks>
    /// A deployment-wide profile is a FLOOR, not a default. Turning one on is a statement about
    /// every client the server serves, so a client cannot step out from under it - it can only ask
    /// for more. The alternative reading, where a client naming a profile replaces the deployment's,
    /// makes the server-wide setting a suggestion: one registration would quietly leave a
    /// FAPI 2.0 deployment serving a client under none of its controls, and nothing about that
    /// registration would look like a decision to weaken the server.
    ///
    /// The combination is per CONTROL rather than a choice between two bundles, because "stricter"
    /// is not a property a bundle has - one profile can demand sender-constrained tokens while
    /// another names a tighter clock window, and picking either bundle whole would drop the other's
    /// demand.
    /// </remarks>
    /// <param name="client">The client whose effective profile is being resolved.</param>
    /// <param name="defaultProfile">The profile the deployment holds every client to.</param>
    public static SecurityProfileRequirements For(ClientInfo client, ClientSecurityProfile defaultProfile)
    {
        var deployment = Resolve(defaultProfile);

        return client.SecurityProfile is not { } chosen
            ? deployment
            : deployment.TightenedBy(Resolve(chosen));
    }

    /// <summary>
    /// This bundle with every control at whichever of the two values concedes less.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each flag is OR-ed, including <see cref="ForbidRefreshTokenRotation"/>, and that one is not a
    /// slip. It removes a control, but the profile removing it introduces two others in its place -
    /// so carrying it over is what keeps a profile whole, while AND-ing it would hand rotation back
    /// to a client under a deployment that had switched it off, dismantling one part of a bundle
    /// the deployment turned on entire.
    /// </para>
    /// <para>
    /// A ceiling is the SMALLER of the two, and an absent ceiling concedes to a present one: no
    /// bound cannot cancel a bound. A tolerance is compared half by half, since the two directions
    /// answer different questions and a profile may tighten one without touching the other.
    /// </para>
    /// </remarks>
    /// <param name="other">The bundle whose demands are added to this one's.</param>
    private SecurityProfileRequirements TightenedBy(SecurityProfileRequirements other)
        // Builder: each step settles one family of controls and leaves the others as it found them, so the
        // steps compose in any order
        => WithRequestControlsTightenedBy(other)
            .WithRequestObjectControlsTightenedBy(other)
            .WithClientAndTokenControlsTightenedBy(other)
            .WithClockTightenedBy(other);

    /// <summary>
    /// This bundle with the controls on the shape of the authorization request and its response tightened by
    /// <paramref name="other"/>.
    /// </summary>
    private SecurityProfileRequirements WithRequestControlsTightenedBy(SecurityProfileRequirements other) => this with
    {
        RequirePkce = RequirePkce || other.RequirePkce,
        RequireS256CodeChallenge = RequireS256CodeChallenge || other.RequireS256CodeChallenge,
        RequirePushedAuthorizationRequests =
            RequirePushedAuthorizationRequests || other.RequirePushedAuthorizationRequests,
        RequireCodeResponseTypeOnly = RequireCodeResponseTypeOnly || other.RequireCodeResponseTypeOnly,
        RequireSignedAuthorizationResponse =
            RequireSignedAuthorizationResponse || other.RequireSignedAuthorizationResponse,
        RequireNonceWithOpenIdScope = RequireNonceWithOpenIdScope || other.RequireNonceWithOpenIdScope,
        RequireStateWithoutOpenIdScope = RequireStateWithoutOpenIdScope || other.RequireStateWithoutOpenIdScope,
        RequirePkceWithPushedRequests = RequirePkceWithPushedRequests || other.RequirePkceWithPushedRequests,
        RequireExactHttpsRedirectUris = RequireExactHttpsRedirectUris || other.RequireExactHttpsRedirectUris,
    };

    /// <summary>
    /// This bundle with the controls on the request object tightened by <paramref name="other"/>.
    /// </summary>
    private SecurityProfileRequirements WithRequestObjectControlsTightenedBy(SecurityProfileRequirements other)
        => this with
        {
            RequireStrictRequestObjectProcessing =
                RequireStrictRequestObjectProcessing || other.RequireStrictRequestObjectProcessing,
            RequireSignedRequestObject = RequireSignedRequestObject || other.RequireSignedRequestObject,
            MaxRequestObjectLifetime = Tighter(MaxRequestObjectLifetime, other.MaxRequestObjectLifetime),
            RequireIssuerAudienceInRequestObject =
                RequireIssuerAudienceInRequestObject || other.RequireIssuerAudienceInRequestObject,
        };

    /// <summary>
    /// This bundle with the controls on the client's credentials and on the tokens it is issued tightened by
    /// <paramref name="other"/>.
    /// </summary>
    private SecurityProfileRequirements WithClientAndTokenControlsTightenedBy(SecurityProfileRequirements other)
        => this with
        {
            RequireSenderConstrainedTokens =
                RequireSenderConstrainedTokens || other.RequireSenderConstrainedTokens,
            RequireConfidentialClient = RequireConfidentialClient || other.RequireConfidentialClient,
            RequireKeyBasedClientAuthentication =
                RequireKeyBasedClientAuthentication || other.RequireKeyBasedClientAuthentication,
            RequireStringAudienceInClientAssertion =
                RequireStringAudienceInClientAssertion || other.RequireStringAudienceInClientAssertion,
            ForbidRefreshTokenRotation = ForbidRefreshTokenRotation || other.ForbidRefreshTokenRotation,
            RequireFapiSigningAlgorithms = RequireFapiSigningAlgorithms || other.RequireFapiSigningAlgorithms,
            ForbidRsa1_5KeyManagement = ForbidRsa1_5KeyManagement || other.ForbidRsa1_5KeyManagement,
            RequireMatchingClientIdentifiers =
                RequireMatchingClientIdentifiers || other.RequireMatchingClientIdentifiers,
            RequireHttpsJwksUri = RequireHttpsJwksUri || other.RequireHttpsJwksUri,
        };

    /// <summary>
    /// This bundle with its clock ceiling and default tolerance tightened by <paramref name="other"/>.
    /// </summary>
    private SecurityProfileRequirements WithClockTightenedBy(SecurityProfileRequirements other) => this with
    {
        MaxClockSkew = Tighter(MaxClockSkew, other.MaxClockSkew),
        DefaultClockSkew = new ClockSkew
        {
            Past = Shorter(DefaultClockSkew.Past, other.DefaultClockSkew.Past),
            Future = Shorter(DefaultClockSkew.Future, other.DefaultClockSkew.Future),
        },
    };

    /// <summary>
    /// The tighter of two ceilings, where absence means no ceiling and therefore concedes.
    /// </summary>
    private static TimeSpan? Tighter(TimeSpan? left, TimeSpan? right) => (left, right) switch
    {
        ({ } a, { } b) => Shorter(a, b),
        ({ } a, null) => a,
        (null, { } b) => b,
        _ => null,
    };

    /// <summary>
    /// The shorter of two windows, which is the one granting less.
    /// </summary>
    private static TimeSpan Shorter(TimeSpan left, TimeSpan right) => left < right ? left : right;
}
