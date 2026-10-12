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

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// Confirms that an authorization response came from the server the request was sent to, per RFC 9207.
/// </summary>
/// <remarks>
/// The attack this closes is mix-up (RFC 9700 section 4.4). A client that talks to more than one
/// provider, tricked into sending its user to an attacker-controlled one, gets a response back that
/// looks like an ordinary success - and hands the authorization code, plus the PKCE verifier, to the
/// wrong party. Nothing inside the code says who issued it, so without this check the client only
/// discovers the mistake when the token endpoint refuses it, which is one round trip too late.
/// The check has to run before the code is redeemed for exactly that reason, and before an error
/// response is believed: RFC 9207 section 2.4 says "For error responses, clients MUST NOT assume that
/// the error originates from the intended authorization server", so an unverified error code is an
/// attacker's claim rather than the provider's.
/// </remarks>
/// <param name="metadataProvider">Tells whether this provider advertises the parameter.</param>
/// <param name="options">Local policy, where the specification defers to it.</param>
internal sealed class ResponseIssuerValidator(
    IProviderMetadataProvider metadataProvider,
    Microsoft.Extensions.Options.IOptions<ResponseIssuerOptions> options)
    : IResponseIssuerValidator
{
    public async Task ValidateAsync(ResponseIssuers issuers, CancellationToken cancellationToken = default)
    {
        // Section 4: "if a client receives an authorization response that contains multiple issuer
        // identifiers, the client MUST reject the response if these issuer identifiers do not match".
        // Checked first and against each other rather than against the expectation, because two
        // identifiers that disagree are a broken response whichever of them happens to be right.
        if (issuers.Parameter is { } parameter && issuers.IdentityTokenClaim is { } claim
            && !Matches(parameter, claim))
        {
            throw new AuthorizationResponseException(
                "The authorization response names one issuer in its iss parameter and another in the ID Token.");
        }

        // Section 4 also says the parameter itself becomes unnecessary when the issuer arrives by other
        // means and is checked the same way: "this is the case when OpenID Connect response types that
        // return an ID Token from the authorization endpoint (e.g., response_type=code id_token) or
        // [JARM] are used". So an ID Token from the authorization endpoint stands in for the parameter,
        // which is what keeps a JARM response - carrying its issuer inside the JWT and nothing on top -
        // from being refused for lacking a parameter it was never supposed to need.
        var stated = issuers.Parameter ?? issuers.IdentityTokenClaim;

        if (stated is null)
        {
            await RefuseIfTheProviderShouldHaveStatedItAsync(issuers, cancellationToken);
            return;
        }

        // Section 2.4: compare against "the issuer identifier of the authorization server where the
        // authorization request was sent to", by "simple string comparison as defined in Section 6.2.1
        // of [RFC3986]" - the tier with no normalisation at all, so a trailing slash or a differently
        // cased host is a different issuer rather than a forgiving one.
        if (!Matches(stated, issuers.Expected))
        {
            throw new AuthorizationResponseException(
                "The authorization response came from a different issuer than the request was sent to.");
        }

        await RefuseIfUnadvertisedAsync(issuers, cancellationToken);
    }

    /// <summary>
    /// Simple string comparison, RFC 3986 section 6.2.1: character for character, nothing normalised.
    /// </summary>
    private static bool Matches(string left, string right) => string.Equals(left, right, StringComparison.Ordinal);

    /// <summary>
    /// Handles a response that named no issuer at all.
    /// </summary>
    /// <remarks>
    /// Section 2.4 makes exactly one case a MUST: "Clients MUST reject authorization responses without
    /// the iss parameter from authorization servers that do support the parameter according to the
    /// client's configuration." Support is read from the provider's metadata, where section 3 gives the
    /// flag a default: "If omitted, the default value is false."
    /// Beyond that case the specification hands the decision over - a client "MAY accept authorization
    /// responses that do not contain the iss parameter or reject them" - which is what
    /// <see cref="ResponseIssuerOptions.RequireIssuer"/> exposes rather than deciding here.
    /// </remarks>
    private async Task RefuseIfTheProviderShouldHaveStatedItAsync(
        ResponseIssuers issuers,
        CancellationToken cancellationToken)
    {
        if (options.Value.RequireIssuer)
        {
            throw new AuthorizationResponseException(
                "The authorization response names no issuer, and this client requires one.");
        }

        var metadata = await metadataProvider.GetMetadataAsync(cancellationToken);
        if (metadata.AuthorizationResponseIssParameterSupported is true)
        {
            throw new AuthorizationResponseException(
                $"The authorization response names no issuer, though '{issuers.Expected}' advertises that it sends one.");
        }
    }

    /// <summary>
    /// Handles an issuer that matched, from a provider that never said it would send one.
    /// </summary>
    /// <remarks>
    /// Section 2.4: "Clients SHOULD discard authorization responses with the iss parameter from
    /// authorization servers that do not indicate their support for the parameter." The very next
    /// sentence is why this is not the default: "However, there might be legitimate authorization
    /// servers that provide the iss parameter without indicating their support in their metadata. Local
    /// policy or configuration can determine whether to accept such responses". Discarding by default
    /// would refuse those providers over a correct value they volunteered, so the SHOULD is offered as
    /// a setting and the specification's own escape clause is the reason.
    /// </remarks>
    private async Task RefuseIfUnadvertisedAsync(ResponseIssuers issuers, CancellationToken cancellationToken)
    {
        if (!options.Value.DiscardUnadvertisedIssuer || issuers.Parameter is null)
            return;

        var metadata = await metadataProvider.GetMetadataAsync(cancellationToken);
        if (metadata.AuthorizationResponseIssParameterSupported is not true)
        {
            throw new AuthorizationResponseException(
                $"The authorization response carries an iss parameter, but '{issuers.Expected}' does not advertise sending one.");
        }
    }
}
