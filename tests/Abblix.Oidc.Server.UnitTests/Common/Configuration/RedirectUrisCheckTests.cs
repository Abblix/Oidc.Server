// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A tenant declaring a client that redirects to a scheme the user agent runs as script, or to a URI that is not
/// absolute, does not start, whichever kind of client it is, and the refusal names the client.
/// </summary>
public class RedirectUrisCheckTests
{
    private const string ClientId = "script-redirect";

    [Theory]
    [InlineData("javascript:alert(1)", ApplicationTypes.Web, false)]
    [InlineData("data:text/html,callback", ApplicationTypes.Web, false)]
    [InlineData("VBScript:msgbox(1)", ApplicationTypes.Web, false)]
    [InlineData("javascript:alert(1)", ApplicationTypes.Native, false)]
    [InlineData("javascript:alert(1)", ApplicationTypes.Web, true)]
    [InlineData("data:text/html,signed-out", ApplicationTypes.Native, true)]
    public void AClient_RedirectingToAScriptScheme_IsRefused(string uri, string applicationType, bool postLogout)
    {
        var client = new ClientInfo(ClientId) { ApplicationType = applicationType };
        if (postLogout)
            client.PostLogoutRedirectUris = [new Uri(uri)];
        else
            client.RedirectUris = [new Uri(uri)];

        Assert.Contains($"'{ClientId}'", Assert.Single(Check(client)));
    }

    /// <summary>
    /// The settings values a URL parser of a browser turns into a javascript URI, by removing a tab or a newline
    /// anywhere and a control character in front, beside a plain relative path.
    /// </summary>
    public static TheoryData<string, string, bool> NotAbsoluteUris()
    {
        var data = new TheoryData<string, string, bool>();
        var rows =
            from uri in (string[])["java\tscript:alert(1)", "java\nscript:alert(1)", "\u0001javascript:alert(1)", "/callback"]
            from applicationType in (string[])[ApplicationTypes.Web, ApplicationTypes.Native]
            from postLogout in (bool[])[false, true]
            select (uri, applicationType, postLogout);

        foreach (var (uri, applicationType, postLogout) in rows)
            data.Add(uri, applicationType, postLogout);

        return data;
    }

    /// <summary>
    /// RFC 6749 section 3.1.2: "The redirection endpoint URI MUST be an absolute URI". The post-logout redirect URIs
    /// are held to it as well, since the user agent is sent to them the same way. The values arrive through the
    /// configuration binder, the way a host's settings reach a client, which reads each of them as a relative URI.
    /// </summary>
    [Theory]
    [MemberData(nameof(NotAbsoluteUris))]
    public void AClient_RedirectingToAUriThatIsNotAbsolute_IsRefusedOnceByThisCheck(
        string uri,
        string applicationType,
        bool postLogout)
    {
        var client = Bound(uri, applicationType, postLogout);

        var bound = Assert.Single(postLogout ? client.PostLogoutRedirectUris : client.RedirectUris);
        Assert.False(bound.IsAbsoluteUri);
        Assert.Contains($"'{ClientId}'", Assert.Single(Check(client)));
        Assert.Empty(NativeCheck(client));
    }

    /// <summary>
    /// A redirection endpoint URI written with a fragment, for each kind of client and in both lists.
    /// </summary>
    public static TheoryData<string, string, bool> UrisWithAFragment()
    {
        var data = new TheoryData<string, string, bool>();
        var rows =
            from applicationType in (string[])[ApplicationTypes.Web, ApplicationTypes.Native]
            from postLogout in (bool[])[false, true]
            let uri = applicationType == ApplicationTypes.Web
                ? "https://app.example.com/cb#section"
                : "com.example.app:/cb#section"
            select (uri, applicationType, postLogout);

        foreach (var (uri, applicationType, postLogout) in rows)
            data.Add(uri, applicationType, postLogout);

        return data;
    }

    /// <summary>
    /// RFC 6749 section 3.1.2: "The endpoint URI MUST NOT include a fragment component". The post-logout redirect URIs
    /// are held to it as well, as dynamic registration holds them.
    /// </summary>
    [Theory]
    [MemberData(nameof(UrisWithAFragment))]
    public void AClient_RedirectingToAUriWithAFragment_IsRefusedOnceByThisCheck(
        string uri,
        string applicationType,
        bool postLogout)
    {
        var client = Bound(uri, applicationType, postLogout);

        Assert.Contains($"'{ClientId}'", Assert.Single(Check(client)));
        Assert.Empty(NativeCheck(client));
    }

    /// <summary>
    /// Among every check the server runs on a tenant's settings, a client otherwise accepted is refused exactly once
    /// for a URI that is not absolute or includes a fragment, and no check fails on it, so a tenant read from a store
    /// is dropped with the refusal logged rather than failing the read.
    /// </summary>
    [Theory]
    [MemberData(nameof(NotAbsoluteUris))]
    [MemberData(nameof(UrisWithAFragment))]
    public void EverySettingsCheck_OnARefusedUri_RefusesOnceWithoutFailing(
        string uri,
        string applicationType,
        bool postLogout)
    {
        Assert.Empty(AllChecks(Bound("com.example.app:/cb", applicationType, postLogout)));

        var client = Bound(uri, applicationType, postLogout);
        Assert.Equal(Assert.Single(Check(client)), Assert.Single(AllChecks(client)).Message);
    }

    /// <summary>
    /// Dynamic registration refuses each of the same values, read from a registration body, so a client the host
    /// declares and one that registers are held to one rule.
    /// </summary>
    [Theory]
    [MemberData(nameof(NotAbsoluteUris))]
    [MemberData(nameof(UrisWithAFragment))]
    public async Task Registration_OfARefusedUri_IsRefused(
        string uri,
        string applicationType,
        bool postLogout)
    {
        var context = RegistrationOf(uri, applicationType, postLogout);

        var error = postLogout
            ? await new PostLogoutRedirectUrisValidator().ValidateAsync(SingleIssuer.Tenant, context)
            : await new RedirectUrisValidator().ValidateAsync(SingleIssuer.Tenant, context);

        var expected = postLogout ? ErrorCodes.InvalidClientMetadata : ErrorCodes.InvalidRedirectUri;
        Assert.Equal(expected, Assert.IsType<OidcError>(error).Error);
    }

    /// <summary>
    /// The registration check of every URI member refuses a value that is not absolute as well.
    /// </summary>
    [Theory]
    [MemberData(nameof(NotAbsoluteUris))]
    public async Task Registration_OfAUriThatIsNotAbsolute_IsRefusedAsAStoredUri(
        string uri,
        string applicationType,
        bool postLogout)
    {
        var context = RegistrationOf(uri, applicationType, postLogout);

        Assert.Equal(ErrorCodes.InvalidClientMetadata,
            Assert.IsType<OidcError>(await new StoredUriValidator().ValidateAsync(SingleIssuer.Tenant, context)).Error);
    }

    /// <summary>
    /// A refusal shows the value with every control, format and whitespace character but a space percent-encoded, so
    /// a value carrying one cannot break or hide inside the logged line, whichever check refuses it and whether the
    /// value parses as absolute or not.
    /// </summary>
    [Theory]
    [InlineData("java\tscript:alert(1)", ApplicationTypes.Web)]
    [InlineData("java\nscript:alert(1)", ApplicationTypes.Web)]
    [InlineData("\u0001javascript:alert(1)", ApplicationTypes.Web)]
    [InlineData("javascript:alert(1)\ny", ApplicationTypes.Web)]
    [InlineData("javascript:alert(1)​y", ApplicationTypes.Web)]
    [InlineData("https://app.example.com/cb#a\nb", ApplicationTypes.Web)]
    [InlineData("myapp:/cb\ny", ApplicationTypes.Native)]
    [InlineData("myapp:/cb​y", ApplicationTypes.Native)]
    public void ARefusal_ShowsNoInvisibleCharacter(string uri, string applicationType)
    {
        var client = Bound(uri, applicationType, postLogout: false);

        var refusal = Assert.Single(AllChecks(client)).Message;

        Assert.DoesNotContain(refusal, IsInvisible);
    }

    /// <summary>
    /// A value carrying nothing to encode is shown as the settings spell it.
    /// </summary>
    [Fact]
    public void ARefusal_ShowsAPlainValueAsWritten()
        => Assert.Contains("'/callback'", Assert.Single(Check(Bound("/callback", ApplicationTypes.Web, postLogout: false))));

    private static bool IsInvisible(char character)
        => char.IsControl(character)
           || char.GetUnicodeCategory(character) == UnicodeCategory.Format
           || (char.IsWhiteSpace(character) && character != ' ');

    private static ClientRegistrationValidationContext RegistrationOf(string uri, string applicationType, bool postLogout)
    {
        var member = postLogout
            ? ClientRegistrationRequest.Parameters.PostLogoutRedirectUris
            : ClientRegistrationRequest.Parameters.RedirectUris;
        var other = postLogout
            ? ClientRegistrationRequest.Parameters.RedirectUris
            : ClientRegistrationRequest.Parameters.PostLogoutRedirectUris;
        var body = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            [ClientRegistrationRequest.Parameters.ApplicationType] = applicationType,
            [member] = new[] { uri },
            [other] = new[] { applicationType == ApplicationTypes.Web ? "https://app.example.com/cb" : "com.example.app:/cb" },
        });
        var request = JsonSerializer.Deserialize<ClientRegistrationRequest>(body)!;
        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Any other scheme starts, a web client's private-use one included.
    /// </summary>
    [Theory]
    [InlineData("https://app.example.com/cb")]
    [InlineData("myapp:/cb")]
    [InlineData("com.example.app:/cb")]
    public void AClient_RedirectingToAnotherScheme_Starts(string uri)
        => Assert.Empty(Check(new ClientInfo(ClientId)
        {
            RedirectUris = [new Uri(uri)],
            PostLogoutRedirectUris = [new Uri(uri)],
        }));

    /// <summary>
    /// A native app redirecting to a script scheme is refused once, by this check: the native redirect rule leaves
    /// script schemes to it.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ANativeApp_RedirectingToAScriptScheme_IsRefusedOnceByThisCheck(bool postLogout)
    {
        var client = new ClientInfo(ClientId)
        {
            ApplicationType = ApplicationTypes.Native,
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
        };
        if (postLogout)
            client.PostLogoutRedirectUris = [new Uri("javascript:alert(1)")];
        else
            client.RedirectUris = [new Uri("javascript:alert(1)")];

        Assert.Contains($"'{ClientId}'", Assert.Single(Check(client)));
        Assert.Empty(NativeCheck(client));
    }

    /// <summary>
    /// A client bound from settings naming <paramref name="uri"/> as its only redirect or post-logout redirect URI,
    /// and otherwise passing every check: a public client, the native one redirecting to a private-use scheme.
    /// </summary>
    private static ClientInfo Bound(string uri, string applicationType, bool postLogout)
    {
        var member = postLogout ? nameof(ClientInfo.PostLogoutRedirectUris) : nameof(ClientInfo.RedirectUris);
        var other = postLogout ? nameof(ClientInfo.RedirectUris) : nameof(ClientInfo.PostLogoutRedirectUris);
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [nameof(ClientInfo.ClientId)] = ClientId,
                [nameof(ClientInfo.ApplicationType)] = applicationType,
                [nameof(ClientInfo.TokenEndpointAuthMethod)] = ClientAuthenticationMethods.None,
                [$"{member}:0"] = uri,
                [$"{other}:0"] = "com.example.app:/other",
            })
            .Build();

        var client = new ClientInfo(ClientId);
        configuration.Bind(client);
        return client;
    }

    private static TenantDefinition Tenant(ClientInfo client)
        => new() { Id = "acme", Issuer = new Uri("https://auth.example.com"), Clients = [client] };

    private static string[] Check(ClientInfo client)
        => new RedirectUrisCheck().Check([Tenant(client)], new OidcOptions())
            .Select(refusal => refusal.Message).ToArray();

    private static TenantRefusal[] NativeCheck(ClientInfo client)
        => new NativeClientsCheck().Check([Tenant(client)], new OidcOptions()).ToArray();

    private static TenantRefusal[] AllChecks(ClientInfo client)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddOidcServices(_ => { });
        using var provider = services.BuildServiceProvider();
        var tenant = new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri("https://auth.example.com"),
            Clients = [client],
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
        };
        return provider.GetServices<ITenantsCheck>()
            .SelectMany(check => check.Check([tenant], new OidcOptions()))
            .ToArray();
    }
}
