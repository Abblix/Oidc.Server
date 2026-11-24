// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

// A software statement in a metadata document is not read: the document is judged under the rules its reader fixes
public partial class ClientIdMetadataDocumentTests
{
    /// <summary>
    /// A document carrying a statement from an issuer the host trusts is served by its own values alone: the statement's
    /// opt-out of PKCE and its plain-http logo change nothing about the client resolved.
    /// </summary>
    [Fact]
    public async Task AStatementInADocument_ChangesNothingAboutTheClient()
    {
        var document = PublicClientDocument();
        document[RegistrationMembers.SoftwareStatement] = await TrustedStatementIssuer.IssueAsync(new JsonObject
        {
            [RegistrationMembers.PkceRequired] = false,
            [RegistrationMembers.LogoUri] = "http://client.example.com/logo.png",
        });
        Serve(document);
        await using var host = CreateHost(configureServices: TrustedStatementIssuer.TrustIn);

        var client = await FindAsync(host, TenantListing("acme", authority: null));

        Assert.True(client.TryGetSuccess(out var found), client.ToString());
        Assert.True(found.PkceRequired);
        Assert.Null(found.LogoUri);
    }
}
