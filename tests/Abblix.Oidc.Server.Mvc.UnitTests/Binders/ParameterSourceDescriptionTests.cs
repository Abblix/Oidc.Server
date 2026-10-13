// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using Parameters = Abblix.Oidc.Server.Model.TokenRequest.Parameters;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Binders;

/// <summary>
/// The binder each parameter names leaves its source to the action, so a host that describes its API, the library's
/// endpoints included, sees the parameters of the token request as form fields and its Authorization header as a
/// header rather than as custom-bound values.
/// </summary>
public class ParameterSourceDescriptionTests
{
    [Theory]
    [InlineData(Parameters.GrantType)]
    [InlineData(Parameters.Code)]
    [InlineData(Parameters.Scope)]
    public void ATokenRequestParameterIsDescribedAsAFormField(string parameter)
        => Assert.Equal(BindingSource.Form, SourceOf(parameter));

    [Fact]
    public void TheAuthorizationHeaderIsDescribedAsAHeader()
        => Assert.Equal(BindingSource.Header, SourceOf(HeaderNames.Authorization));

    private static BindingSource? SourceOf(string parameter)
    {
        var services = new ServiceCollection().AddLogging().AddOidcMvc();
        services.AddMvcCore().AddApiExplorer();

        var token = services.BuildServiceProvider().GetRequiredService<IApiDescriptionGroupCollectionProvider>()
            .ApiDescriptionGroups.Items
            .SelectMany(group => group.Items)
            .Single(description => description.RelativePath == "connect/token");

        return token.ParameterDescriptions.Single(description => description.Name == parameter).Source;
    }
}
