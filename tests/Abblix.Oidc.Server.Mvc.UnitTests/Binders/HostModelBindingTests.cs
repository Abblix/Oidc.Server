// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.ComponentModel.DataAnnotations;
using System.Globalization;
using Abblix.Oidc.Server.Mvc.Binders;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using AuthorizationRequest = Abblix.Oidc.Server.Mvc.Model.AuthorizationRequest;
using Parameters = Abblix.Oidc.Server.Model.AuthorizationRequest.Parameters;
using TokenRequest = Abblix.Oidc.Server.Mvc.Model.TokenRequest;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Binders;

/// <summary>
/// The package is installed into a host's own MVC application, so it changes how its own request models bind and
/// nothing else: a host's model binds as it would without the package.
/// </summary>
public class HostModelBindingTests
{
    private static readonly IServiceProvider Services =
        new ServiceCollection().AddLogging().AddOidcMvc().BuildServiceProvider();

    [Fact]
    public void ARequiredPropertyOfAHostModelIsNotMadeBindingRequired()
        => Assert.False(MetadataFor(typeof(HostModel), nameof(HostModel.Name)).IsBindingRequired);

    [Fact]
    public void ARequiredPropertyOfAPackageModelIsBindingRequired()
        => Assert.True(MetadataFor(typeof(TokenRequest), nameof(TokenRequest.GrantType)).IsBindingRequired);

    [Fact]
    public void ACultureListOfAHostModelGetsTheBindingItWouldGetAnyway()
        => Assert.IsNotType<CultureInfoBinder>(BinderFor(typeof(HostModel), nameof(HostModel.Languages)));

    /// <summary>
    /// ui_locales is "a space-separated list of BCP47 language tag values" (OIDC Core 1.0 section 3.1.2.1), which the
    /// package's own culture binding reads into one culture per tag.
    /// </summary>
    [Fact]
    public async Task UiLocalesOfAPackageModelIsReadAsASpaceSeparatedList()
    {
        var httpContext = new DefaultHttpContext { RequestServices = Services };
        httpContext.Request.QueryString = new QueryString("?ui_locales=en%20fr");

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var context = new DefaultModelBindingContext
        {
            ActionContext = actionContext,
            ModelMetadata = MetadataFor(typeof(AuthorizationRequest), nameof(AuthorizationRequest.UiLocales)),
            FieldName = nameof(AuthorizationRequest.UiLocales),
            ModelName = Parameters.UiLocales,
            ModelState = actionContext.ModelState,
            ValueProvider = new CompositeValueProvider(
            [
                new FormValueProvider(BindingSource.Form, FormCollection.Empty, CultureInfo.InvariantCulture),
                new QueryStringValueProvider(BindingSource.Query, httpContext.Request.Query, CultureInfo.InvariantCulture),
            ]),
        };

        await BinderFor(typeof(AuthorizationRequest), nameof(AuthorizationRequest.UiLocales)).BindModelAsync(context);

        var cultures = Assert.IsType<CultureInfo[]>(context.Result.Model);
        Assert.Equal(["en", "fr"], cultures.Select(culture => culture.Name));
    }

    private static ModelMetadata MetadataFor(Type container, string property)
        => Services.GetRequiredService<IModelMetadataProvider>().GetMetadataForProperty(container, property);

    private static IModelBinder BinderFor(Type container, string property)
    {
        var metadata = MetadataFor(container, property);
        var attributes = container.GetProperty(property)!.GetCustomAttributes(inherit: true);

        return Services.GetRequiredService<IModelBinderFactory>().CreateBinder(new ModelBinderFactoryContext
        {
            Metadata = metadata,
            BindingInfo = BindingInfo.GetBindingInfo(attributes, metadata),
            CacheToken = null,
        });
    }

    /// <summary>A model a host declares itself.</summary>
    public sealed class HostModel
    {
        [Required]
        public string? Name { get; set; }

        public CultureInfo[]? Languages { get; set; }
    }
}
