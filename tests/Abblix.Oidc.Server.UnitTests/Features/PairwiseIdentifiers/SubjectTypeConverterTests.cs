// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.PairwiseIdentifiers;

/// <summary>
/// Unit tests for <see cref="SubjectTypeConverter"/> verifying pairwise subject derivation per
/// OIDC Core Section 8.1, in particular the sector identifier fallback chain for statically configured
/// clients without an explicit sector identifier.
/// </summary>
public class SubjectTypeConverterTests
{
    private const string Subject = "user_123";

    // Test-only salt: 32 zero bytes, base64-encoded.
    private static readonly string TestSalt = Convert.ToBase64String(new byte[32]);

    private static SubjectTypeConverter CreateConverter() => new(new PairwiseSubjectSettings { Salt = TestSalt });

    private static ClientInfo CreatePairwiseClient(
        string clientId,
        string? sectorIdentifier = null,
        Uri[]? redirectUris = null,
        string? deliveryMode = null,
        Uri? notificationEndpoint = null,
        Uri? jwksUri = null) => new(clientId)
    {
        SubjectType = SubjectTypes.Pairwise,
        SectorIdentifier = sectorIdentifier,
        RedirectUris = redirectUris ?? [],
        BackChannelTokenDeliveryMode = deliveryMode,
        BackChannelClientNotificationEndpoint = notificationEndpoint,
        JwksUri = jwksUri,
    };

    /// <summary>
    /// OIDC Core Section 8.1: without an explicit sector identifier the sector is the host component of
    /// the registered redirect_uri - two statically configured clients of the same sector must
    /// derive the same pairwise subject. The previous client_id fallback broke exactly this.
    /// </summary>
    [Fact]
    public void Convert_NoSectorIdentifier_DerivesSectorFromRedirectUriHost()
    {
        var converter = CreateConverter();
        var clientA = CreatePairwiseClient("client-a", redirectUris: [new Uri("https://app.example.com/cb1")]);
        var clientB = CreatePairwiseClient("client-b", redirectUris: [new Uri("https://app.example.com/cb2")]);

        Assert.Equal(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// An explicit sector identifier takes precedence over the redirect_uri host fallback.
    /// </summary>
    [Fact]
    public void Convert_ExplicitSectorIdentifier_OverridesRedirectUriHost()
    {
        var converter = CreateConverter();
        var withSector = CreatePairwiseClient(
            "client-a", sectorIdentifier: "sector.example.com",
            redirectUris: [new Uri("https://app.example.com/cb")]);
        var hostDerived = CreatePairwiseClient(
            "client-b", redirectUris: [new Uri("https://app.example.com/cb")]);

        Assert.NotEqual(converter.Convert(Subject, withSector), converter.Convert(Subject, hostDerived));
    }

    /// <summary>
    /// Custom-scheme redirect URIs of native clients (RFC 8252 Section 7.1) carry no meaningful host:
    /// the single-slash form parses with an empty Host, and the authority form puts an arbitrary
    /// path-like segment there - either would merge unrelated clients into one shared sector,
    /// giving them identical pairwise subjects and defeating the isolation pairwise subject
    /// types exist to provide (OIDC Core Section 8.1). The client_id fallback applies instead.
    /// </summary>
    [Theory]
    [InlineData("com.example.one:/oauth2redirect", "com.example.two:/oauth2redirect")]
    [InlineData("app-one://callback", "app-two://callback")]
    public void Convert_CustomSchemeRedirectUri_FallsBackToClientId(string redirectUriA, string redirectUriB)
    {
        var converter = CreateConverter();
        var clientA = CreatePairwiseClient("client-a", redirectUris: [new Uri(redirectUriA)]);
        var clientB = CreatePairwiseClient("client-b", redirectUris: [new Uri(redirectUriB)]);

        Assert.NotEqual(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// Different sectors must produce unlinkable identifiers for the same subject - the core
    /// privacy property of pairwise subject types.
    /// </summary>
    [Fact]
    public void Convert_DifferentSectors_ProduceDifferentSubjects()
    {
        var converter = CreateConverter();
        var sectorOne = CreatePairwiseClient("client-a", redirectUris: [new Uri("https://one.example.com/cb")]);
        var sectorTwo = CreatePairwiseClient("client-b", redirectUris: [new Uri("https://two.example.com/cb")]);

        Assert.NotEqual(converter.Convert(Subject, sectorOne), converter.Convert(Subject, sectorTwo));
    }

    /// <summary>
    /// A pairwise subject is stable: the same (subject, sector) always seals to the same value, so a client sees a
    /// consistent identifier for the user across logins - the core stability guarantee of OIDC Core Section 8.1.
    /// </summary>
    [Fact]
    public void Convert_SameSubjectAndClient_IsDeterministic()
    {
        var converter = CreateConverter();
        var client = CreatePairwiseClient("client-a", redirectUris: [new Uri("https://app.example.com/cb")]);

        Assert.Equal(converter.Convert(Subject, client), converter.Convert(Subject, client));
    }

    /// <summary>
    /// The pairwise identifier is reversible: ConvertBack opens it back to the exact original subject, and the sealed
    /// value is not the bare subject - this is what lets the server carry the pseudonym in tokens yet still resolve
    /// the real user.
    /// </summary>
    [Fact]
    public void Recover_AfterConvert_ReturnsOriginalSubject()
    {
        var converter = CreateConverter();
        var client = CreatePairwiseClient("client-a", redirectUris: [new Uri("https://app.example.com/cb")]);

        var pairwise = converter.Convert(Subject, client);

        Assert.NotEqual(Subject, pairwise);
        Assert.Equal(Subject, converter.ConvertBack(pairwise, client));
    }

    /// <summary>
    /// Sector, not client id, determines the identifier: two distinct clients sharing an explicit sector_identifier
    /// seal the same subject to the same value, so a sector's back-ends see one consistent identifier (OIDC Core
    /// Section 8.1).
    /// </summary>
    [Fact]
    public void Convert_SameExplicitSectorIdentifier_DifferentClients_ProduceSameSubject()
    {
        var converter = CreateConverter();
        var clientA = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");
        var clientB = CreatePairwiseClient("client-b", sectorIdentifier: "sector.example.com");

        Assert.Equal(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// Different sectors stay unlinkable: the same subject under two distinct explicit sector_identifiers seals to
    /// different values, the privacy property pairwise subject types exist to provide.
    /// </summary>
    [Fact]
    public void Convert_DifferentExplicitSectorIdentifiers_ProduceDifferentSubjects()
    {
        var converter = CreateConverter();
        var clientA = CreatePairwiseClient("client-a", sectorIdentifier: "one.example.com");
        var clientB = CreatePairwiseClient("client-b", sectorIdentifier: "two.example.com");

        Assert.NotEqual(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// A pairwise identifier sealed for one sector cannot be opened under another: the sector is bound as associated
    /// data, so ConvertBack under the wrong client's sector returns null instead of a wrong or forged subject, letting
    /// the caller reject the token.
    /// </summary>
    [Fact]
    public void Recover_UnderDifferentSector_ReturnsNull()
    {
        var converter = CreateConverter();
        var sealingClient = CreatePairwiseClient("client-a", sectorIdentifier: "one.example.com");
        var otherSectorClient = CreatePairwiseClient("client-b", sectorIdentifier: "two.example.com");

        var pairwise = converter.Convert(Subject, sealingClient);

        Assert.Null(converter.ConvertBack(pairwise, otherSectorClient));
    }

    /// <summary>
    /// A public client's subject is not transformed: Convert returns it unchanged, so the client sees the real
    /// subject (OIDC Core Section 8, the public subject type).
    /// </summary>
    [Fact]
    public void Convert_PublicClient_ReturnsSubjectUnchanged()
    {
        var converter = CreateConverter();
        var client = new ClientInfo("client-pub") { SubjectType = SubjectTypes.Public };

        Assert.Equal(Subject, converter.Convert(Subject, client));
    }

    /// <summary>
    /// A public client's subject passes through on the way back too: ConvertBack returns it unchanged, since a public
    /// subject is never sealed.
    /// </summary>
    [Fact]
    public void Recover_PublicClient_ReturnsSubjectUnchanged()
    {
        var converter = CreateConverter();
        var client = new ClientInfo("client-pub") { SubjectType = SubjectTypes.Public };

        Assert.Equal(Subject, converter.ConvertBack(Subject, client));
    }

    /// <summary>
    /// The subject is part of the seal, not ignored: two different users in the same sector get different pairwise
    /// identifiers, so a sector cannot conflate two accounts into one.
    /// </summary>
    [Fact]
    public void Convert_DifferentSubjects_SameSector_ProduceDifferentSubjects()
    {
        var converter = CreateConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");

        Assert.NotEqual(converter.Convert("user-one", client), converter.Convert("user-two", client));
    }

    /// <summary>
    /// Pairwise identifiers require configuration: a converter built without pairwise settings fails loudly when a
    /// pairwise client asks to seal a subject, rather than silently leaking the real subject.
    /// </summary>
    [Fact]
    public void Convert_PairwiseWithoutSettings_Throws()
    {
        var converter = new SubjectTypeConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");

        Assert.Throws<InvalidOperationException>(() => converter.Convert(Subject, client));
    }

    /// <summary>
    /// The same fail-loud guard covers the reverse direction: a converter without pairwise settings cannot open a
    /// pairwise identifier and throws instead of returning a wrong subject.
    /// </summary>
    [Fact]
    public void Recover_PairwiseWithoutSettings_Throws()
    {
        var configured = CreateConverter();
        var unconfigured = new SubjectTypeConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");
        var pairwise = configured.Convert(Subject, client);

        Assert.Throws<InvalidOperationException>(() => unconfigured.ConvertBack(pairwise, client));
    }

    /// <summary>
    /// The identifier is stable across converter instances sharing the salt, not tied to one process: a pseudonym
    /// sealed by one instance is reproduced and opened by another, so pairwise identifiers survive a restart and work
    /// on a stateless server farm.
    /// </summary>
    [Fact]
    public void ConvertAndRecover_AreStableAcrossInstances_WithSameSalt()
    {
        var instanceA = CreateConverter();
        var instanceB = CreateConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");

        var sealedByA = instanceA.Convert(Subject, client);

        Assert.Equal(sealedByA, instanceB.Convert(Subject, client));
        Assert.Equal(Subject, instanceB.ConvertBack(sealedByA, client));
    }

    /// <summary>
    /// A syntactically invalid pseudonym (not even valid base64url) returns null rather than being mis-parsed into a
    /// bogus subject, letting the caller reject the token.
    /// </summary>
    [Fact]
    public void Recover_MalformedPseudonym_ReturnsNull()
    {
        var converter = CreateConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");

        Assert.Null(converter.ConvertBack("not valid base64url!!", client));
    }

    /// <summary>
    /// The last-resort sector fallback is the client id: two clients with neither a sector_identifier nor any
    /// redirect URIs (for example client_credentials-only clients) stay isolated, each sealing the same subject to a
    /// different value.
    /// </summary>
    [Fact]
    public void Convert_NoSectorIdentifierNoRedirectUris_FallsBackToClientId()
    {
        var converter = CreateConverter();
        var clientA = CreatePairwiseClient("client-a");
        var clientB = CreatePairwiseClient("client-b");

        Assert.NotEqual(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// The pairwise identifier stays compact: it is the base64url of an AES key wrap of the subject, so its length
    /// is a small, bounded function of the subject length - 16 wrapped bytes (22 base64url chars) for a subject up
    /// to one 8-byte semiblock, then 8 more wrapped bytes per further semiblock. This pins the size contract so an
    /// unexpected growth (which would inflate every token's sub) is caught by a regression.
    /// </summary>
    [Theory]
    [InlineData(1, 22)]
    [InlineData(8, 22)]
    [InlineData(9, 32)]
    [InlineData(16, 32)]
    [InlineData(17, 43)]
    [InlineData(36, 64)]
    public void Convert_PairwiseIdentifierLength_IsBoundedBySubjectLength(int subjectByteLength, int expectedLength)
    {
        var converter = CreateConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");
        var subject = new string('a', subjectByteLength); // ASCII, one byte per character

        var pairwise = converter.Convert(subject, client);

        Assert.Equal(expectedLength, pairwise.Length);
    }
    /// <summary>
    /// Two backchannel clients of one sector that registered no redirect URI still derive the same
    /// pairwise subject, taking the host from the URI their delivery mode names.
    /// </summary>
    /// <remarks>
    /// CIBA Core 1.0 Section 4 puts the jwks_uri in the redirect URI's place for poll and ping, and the
    /// backchannel_client_notification_endpoint for push. Without this the client_id fallback was
    /// reached, making identifiers per-client where the specification makes them per-sector - which is
    /// the whole point of a sector, so two genuinely-one-deployment clients could not recognise a user
    /// as the same person.
    /// </remarks>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Push)]
    [InlineData(BackchannelTokenDeliveryModes.Poll)]
    [InlineData(BackchannelTokenDeliveryModes.Ping)]
    public void Convert_BackchannelClientsOfOneSector_DeriveTheSameSubject(string deliveryMode)
    {
        var converter = CreateConverter();
        var isPush = deliveryMode == BackchannelTokenDeliveryModes.Push;

        ClientInfo Client(string clientId, string path) => CreatePairwiseClient(
            clientId,
            deliveryMode: deliveryMode,
            notificationEndpoint: isPush ? new Uri($"https://one.example.com/{path}") : null,
            jwksUri: isPush ? null : new Uri($"https://one.example.com/{path}"));

        Assert.Equal(
            converter.Convert(Subject, Client("client-a", "a")),
            converter.Convert(Subject, Client("client-b", "b")));
    }

    /// <summary>
    /// A ping client's sector is its jwks_uri, not its notification endpoint.
    /// </summary>
    /// <remarks>
    /// Ping registers both, so grouping it by "has a notification endpoint" instead of by the mode the
    /// specification names is the plausible mistake, and it is invisible to every test where the two
    /// hosts agree. These two clients share a jwks_uri host and differ on the notification endpoint, so
    /// only the correct grouping makes them one sector.
    /// </remarks>
    [Fact]
    public void Convert_PingClient_TakesTheSectorFromTheJwksUriNotTheNotificationEndpoint()
    {
        var converter = CreateConverter();

        var clientA = CreatePairwiseClient(
            "client-a",
            deliveryMode: BackchannelTokenDeliveryModes.Ping,
            notificationEndpoint: new Uri("https://notify-a.example.com/cb"),
            jwksUri: new Uri("https://keys.example.com/a.jwks"));

        var clientB = CreatePairwiseClient(
            "client-b",
            deliveryMode: BackchannelTokenDeliveryModes.Ping,
            notificationEndpoint: new Uri("https://notify-b.example.com/cb"),
            jwksUri: new Uri("https://keys.example.com/b.jwks"));

        Assert.Equal(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// A registered redirect URI still decides the sector for a client that also has a delivery mode.
    /// </summary>
    /// <remarks>
    /// The order is what keeps every already-issued pseudonym openable: the sector is the seal's
    /// associated data, so a client whose sector moves loses every identifier it ever handed out. Only
    /// clients that had NO redirect URI - and whose sector was therefore the client id - change here.
    /// </remarks>
    [Fact]
    public void Convert_BackchannelClientWithARedirectUri_KeepsTheRedirectUriSector()
    {
        var converter = CreateConverter();

        var backchannel = CreatePairwiseClient(
            "client-a",
            redirectUris: [new Uri("https://app.example.com/cb")],
            deliveryMode: BackchannelTokenDeliveryModes.Push,
            notificationEndpoint: new Uri("https://notify.example.com/cb"));

        var plain = CreatePairwiseClient("client-b", redirectUris: [new Uri("https://app.example.com/cb")]);

        Assert.Equal(converter.Convert(Subject, backchannel), converter.Convert(Subject, plain));
    }

    /// <summary>
    /// With no delivery mode the client id is still the last resort, and two such clients stay apart.
    /// </summary>
    /// <remarks>
    /// This is what stops the new fallback from widening: a client that registered a jwks_uri without
    /// any backchannel mode is an ordinary client publishing its keys, and merging two of them into one
    /// sector would seal identical pseudonyms for unrelated parties.
    /// </remarks>
    [Fact]
    public void Convert_NoDeliveryMode_StillFallsBackToTheClientId()
    {
        var converter = CreateConverter();
        var jwksUri = new Uri("https://keys.example.com/jwks");

        var clientA = CreatePairwiseClient("client-a", jwksUri: jwksUri);
        var clientB = CreatePairwiseClient("client-b", jwksUri: jwksUri);

        Assert.NotEqual(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }
    /// <summary>
    /// Two native clients that publish keys on one host stay in separate sectors.
    /// </summary>
    /// <remarks>
    /// The redirect-URI branch above only considers http(s) URIs, so a native client registering
    /// <c>com.example.app:/oauth2redirect</c> falls PAST it - and would land on the backchannel URI
    /// if that branch did not first require that no redirect URI was registered at all. Two
    /// unrelated apps whose keys sit on one hosting provider would then seal identical pseudonyms
    /// for the same person, which is exactly the collision the custom-scheme paragraph exists to
    /// prevent. The existing custom-scheme row cannot see this: it registers no delivery mode, so
    /// the branch it would have to pass through is never entered.
    /// </remarks>
    [Fact]
    public void Convert_NativeClientsSharingAJwksHost_StayInSeparateSectors()
    {
        var converter = CreateConverter();

        var clientA = CreatePairwiseClient(
            "client-a",
            redirectUris: [new Uri("com.example.one:/oauth2redirect")],
            deliveryMode: BackchannelTokenDeliveryModes.Poll,
            jwksUri: new Uri("https://keys.example.com/a.jwks"));

        var clientB = CreatePairwiseClient(
            "client-b",
            redirectUris: [new Uri("app-two://callback")],
            deliveryMode: BackchannelTokenDeliveryModes.Poll,
            jwksUri: new Uri("https://keys.example.com/b.jwks"));

        Assert.NotEqual(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }
    /// <summary>
    /// Two backchannel clients whose keys sit on one host, named by a scheme that is not the web's, stay in
    /// separate sectors.
    /// </summary>
    /// <remarks>
    /// The host branch is filtered to http(s) for a reason that reads as being about redirect URIs and is
    /// not: a URI spelled <c>com.example.one:/keys</c> is absolute, and its Host is the EMPTY STRING rather
    /// than null - so a chain that reaches for the client id when the host is missing never gets there, and
    /// every client naming such a URI shares the one empty sector. Measured, not reasoned: before the
    /// filter reached this arm these two clients sealed the identical pseudonym for one user. The row above
    /// cannot see it, because it comes in through the redirect URIs.
    /// </remarks>
    [Fact]
    public void Convert_BackchannelClientsWithNonWebKeyUris_StayInSeparateSectors()
    {
        var converter = CreateConverter();

        var clientA = CreatePairwiseClient(
            "client-a",
            deliveryMode: BackchannelTokenDeliveryModes.Poll,
            jwksUri: new Uri("com.example.one:/keys"));

        var clientB = CreatePairwiseClient(
            "client-b",
            deliveryMode: BackchannelTokenDeliveryModes.Poll,
            jwksUri: new Uri("com.example.two:/keys"));

        Assert.NotEqual(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// A statically configured client whose key URI is relative still gets an identifier, rather than
    /// faulting on every token it is issued.
    /// </summary>
    /// <remarks>
    /// The registration validator refuses this shape, and it only ever sees requests that came over the
    /// network - a client written into configuration reaches the converter unrefused. <see cref="Uri.Host"/>
    /// throws on a relative URI rather than returning anything, so the fault would land on token issuance,
    /// far from the file that caused it.
    /// </remarks>
    [Fact]
    public void Convert_BackchannelClientWithARelativeKeyUri_FallsBackRatherThanFaulting()
    {
        var converter = CreateConverter();

        var client = CreatePairwiseClient(
            "client-a",
            deliveryMode: BackchannelTokenDeliveryModes.Poll,
            jwksUri: new Uri("/jwks", UriKind.Relative));

        var withNoKeyUri = CreatePairwiseClient("client-a");

        Assert.Equal(converter.Convert(Subject, withNoKeyUri), converter.Convert(Subject, client));
    }
}
