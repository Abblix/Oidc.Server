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

using Abblix.Oidc.Client.Features.AuthorizationResponses;
using Abblix.Oidc.Client.Features.Discovery;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.UnitTests.Features.AuthorizationResponses;

/// <summary>
/// The RFC 9207 issuer check, whose two client duties run opposite ways round: comparing an issuer
/// that IS present is unconditional, while refusing one that is ABSENT depends on what the provider
/// advertised.
/// </summary>
public class ResponseIssuerValidatorTests
{
    private const string Expected = "https://auth.example.com";
    private const string Attacker = "https://attacker.example.com";

    private sealed class StubMetadataProvider(bool? advertises) : IProviderMetadataProvider
    {
        public Task<ProviderMetadata> GetMetadataAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new ProviderMetadata
            {
                Issuer = Expected,
                AuthorizationResponseIssParameterSupported = advertises,
            });
    }

    private static IResponseIssuerValidator CreateValidator(
        bool? advertises = null,
        Action<ResponseIssuerOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IProviderMetadataProvider>(new StubMetadataProvider(advertises));
        services.AddResponseIssuerValidation(configure);

        return services.BuildServiceProvider().GetRequiredService<IResponseIssuerValidator>();
    }

    private static Task Validate(
        IResponseIssuerValidator validator,
        string? parameter = null,
        string? identityTokenClaim = null)
        => validator.ValidateAsync(
            new ResponseIssuers
            {
                Expected = Expected,
                Parameter = parameter,
                IdentityTokenClaim = identityTokenClaim,
            },
            TestContext.Current.CancellationToken);

    /// <summary>
    /// The attack the whole thing exists for: a response from a provider the request never went to.
    /// Section 2.4 - "If the value does not match the expected issuer identifier, clients MUST reject
    /// the authorization response and MUST NOT proceed with the authorization grant."
    /// </summary>
    [Fact]
    public async Task IssuerFromAnotherProvider_IsRejected()
        => await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => Validate(CreateValidator(advertises: true), parameter: Attacker));

    /// <summary>
    /// Comparison is RFC 3986 section 6.2.1 simple string comparison, so nothing is normalised away.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/")]
    [InlineData("https://AUTH.example.com")]
    [InlineData("https://auth.example.com:443")]
    public async Task IssuerDifferingOnlyByNormalisation_IsRejected(string parameter)
        => await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => Validate(CreateValidator(advertises: true), parameter));

    [Fact]
    public async Task MatchingIssuer_IsAccepted()
        => await Validate(CreateValidator(advertises: true), parameter: Expected);

    /// <summary>
    /// Comparing a present issuer is unconditional - it does not wait for the provider to advertise
    /// support. A provider that sends the parameter without announcing it still gets its value checked.
    /// </summary>
    [Fact]
    public async Task WrongIssuerFromAProviderThatDoesNotAdvertise_IsStillRejected()
        => await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => Validate(CreateValidator(advertises: null), parameter: Attacker));

    /// <summary>
    /// Section 2.4: "Clients MUST reject authorization responses without the iss parameter from
    /// authorization servers that do support the parameter according to the client's configuration."
    /// </summary>
    [Fact]
    public async Task MissingIssuerFromAProviderThatAdvertises_IsRejected()
        => await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => Validate(CreateValidator(advertises: true)));

    /// <summary>
    /// And the other way: section 3 gives the metadata flag the default "false" when omitted, so a
    /// provider that never claimed to send one is not refused for not sending it.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(false)]
    public async Task MissingIssuerFromAProviderThatDoesNotAdvertise_IsAccepted(bool? advertises)
        => await Validate(CreateValidator(advertises));

    /// <summary>
    /// Section 2.4 leaves the stricter stance to the deployment: a client "MAY accept authorization
    /// responses that do not contain the iss parameter or reject them".
    /// </summary>
    [Fact]
    public async Task MissingIssuerWithRequireIssuerSet_IsRejected()
        => await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => Validate(CreateValidator(advertises: null, configure: o => o.RequireIssuer = true)));

    /// <summary>
    /// Section 4 lets an ID Token from the authorization endpoint stand in for the parameter: "When an
    /// authorization response already includes an authorization server's issuer identifier by other
    /// means and this identifier is checked as laid out in Section 2.4, the use and verification of the
    /// iss parameter is not necessary and MAY be omitted."
    /// </summary>
    /// <remarks>
    /// This is the case that a naive reject-if-no-parameter rule breaks, and it breaks it worst for
    /// JARM, where the issuer travels inside the response JWT and no top-level parameter exists at all.
    /// </remarks>
    [Fact]
    public async Task IdentityTokenIssuerStandsInForTheParameter()
        => await Validate(
            CreateValidator(advertises: true, configure: o => o.RequireIssuer = true),
            identityTokenClaim: Expected);

    [Fact]
    public async Task IdentityTokenIssuerFromAnotherProvider_IsRejected()
        => await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => Validate(CreateValidator(advertises: true), identityTokenClaim: Attacker));

    /// <summary>
    /// Section 4: "if a client receives an authorization response that contains multiple issuer
    /// identifiers, the client MUST reject the response if these issuer identifiers do not match."
    /// </summary>
    /// <remarks>
    /// Checked against each other rather than one at a time against the expectation, which is what
    /// makes this case detectable at all: here the parameter is the correct issuer, so a validator that
    /// only ever compared against the expected value would pass the response and never notice that the
    /// ID Token inside it names somebody else.
    /// </remarks>
    [Fact]
    public async Task TwoIssuersThatDisagree_AreRejected()
        => await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => Validate(CreateValidator(advertises: true), parameter: Expected, identityTokenClaim: Attacker));

    [Fact]
    public async Task TwoIssuersThatAgree_AreAccepted()
        => await Validate(CreateValidator(advertises: true), parameter: Expected, identityTokenClaim: Expected);

    /// <summary>
    /// The SHOULD in section 2.4 - discard an issuer from a provider that never advertised sending one -
    /// offered as a setting, because the sentence after it says legitimate providers do exactly that.
    /// </summary>
    [Fact]
    public async Task CorrectIssuerFromAnUnadvertisingProvider_IsAcceptedByDefaultAndRefusedWhenAsked()
    {
        await Validate(CreateValidator(advertises: null), parameter: Expected);

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => Validate(
                CreateValidator(advertises: null, configure: o => o.DiscardUnadvertisedIssuer = true),
                parameter: Expected));
    }
}
