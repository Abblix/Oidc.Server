// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using Abblix.Oidc.Server.Mvc.Binders;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using AuthorizationRequest = Abblix.Oidc.Server.Mvc.Model.AuthorizationRequest;
using Parameters = Abblix.Oidc.Server.Model.AuthorizationRequest.Parameters;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Binders;

/// <summary>
/// Which parameters the refusal of a repetition reaches, read off the binders MVC builds once the package is
/// registered, and what the refusal counts.
/// </summary>
public class SingleValueBinderProviderTests
{
    private static readonly IServiceProvider Services =
        new ServiceCollection().AddLogging().AddOidcMvc().BuildServiceProvider();

    /// <summary>
    /// A parameter of this package's models that takes one value, whether it binds by default or through a binder of
    /// its own, is wrapped.
    /// </summary>
    [Theory]
    [InlineData(nameof(AuthorizationRequest.State))]
    [InlineData(nameof(AuthorizationRequest.RedirectUri))]
    [InlineData(nameof(AuthorizationRequest.UiLocales))]
    [InlineData(nameof(AuthorizationRequest.Claims))]
    [InlineData(nameof(AuthorizationRequest.MaxAge))]
    [InlineData(nameof(AuthorizationRequest.Scope))]
    public void SingleValuedParameterOfThePackageIsWrapped(string property)
        => Assert.IsType<SingleValueBinder>(BinderFor(typeof(AuthorizationRequest), property));

    /// <summary>
    /// A parameter defined as repeatable is left to the binding it would get anyway.
    /// </summary>
    [Fact]
    public void RepeatableParameterIsNotWrapped()
        => Assert.IsNotType<SingleValueBinder>(BinderFor(typeof(AuthorizationRequest), nameof(AuthorizationRequest.Resources)));

    /// <summary>
    /// A host's own model binds as it would without this package, a culture list included.
    /// </summary>
    [Theory]
    [InlineData(nameof(HostModel.Name))]
    [InlineData(nameof(HostModel.Languages))]
    public void HostModelIsNotWrapped(string property)
        => Assert.IsNotType<SingleValueBinder>(BinderFor(typeof(HostModel), property));

    /// <summary>
    /// A value sent twice is refused whether both copies travel in the query, or one in the query and one in the
    /// form, which the value providers would have read as one.
    /// </summary>
    [Theory]
    [InlineData("?state=a&state=b", null)]
    [InlineData("?state=a", "b")]
    public async Task ValueSentTwiceIsRefused(string query, string? formValue)
    {
        var outcome = await BindStateAsync(query, formValue);

        Assert.False(outcome.Result.IsModelSet);
        Assert.Equal(1, outcome.ModelState.ErrorCount);
    }

    [Theory]
    [InlineData("?state=a", null)]
    [InlineData("", "a")]
    public async Task ValueSentOnceIsBound(string query, string? formValue)
    {
        var outcome = await BindStateAsync(query, formValue);

        Assert.Equal("a", outcome.Result.Model);
        Assert.Equal(0, outcome.ModelState.ErrorCount);
    }

    private static IModelBinder BinderFor(Type container, string property)
    {
        var metadataProvider = Services.GetRequiredService<IModelMetadataProvider>();
        var metadata = metadataProvider.GetMetadataForProperty(container, property);
        var attributes = container.GetProperty(property)!.GetCustomAttributes(inherit: true);

        return Services.GetRequiredService<IModelBinderFactory>().CreateBinder(new ModelBinderFactoryContext
        {
            Metadata = metadata,
            BindingInfo = BindingInfo.GetBindingInfo(attributes, metadata),
            CacheToken = null,
        });
    }

    private static async Task<DefaultModelBindingContext> BindStateAsync(string query, string? formValue)
    {
        var httpContext = new DefaultHttpContext { RequestServices = Services };
        httpContext.Request.QueryString = new QueryString(query);
        if (formValue is not null)
        {
            httpContext.Request.ContentType = "application/x-www-form-urlencoded";
            httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues> { [Parameters.State] = formValue });
        }

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var valueProvider = new CompositeValueProvider(
        [
            new FormValueProvider(BindingSource.Form, formValue is null ? FormCollection.Empty : httpContext.Request.Form, CultureInfo.InvariantCulture),
            new QueryStringValueProvider(BindingSource.Query, httpContext.Request.Query, CultureInfo.InvariantCulture),
        ]);

        var context = new DefaultModelBindingContext
        {
            ActionContext = actionContext,
            ModelMetadata = Services.GetRequiredService<IModelMetadataProvider>()
                .GetMetadataForProperty(typeof(AuthorizationRequest), nameof(AuthorizationRequest.State)),
            ModelName = Parameters.State,
            ModelState = actionContext.ModelState,
            ValueProvider = valueProvider,
        };

        await BinderFor(typeof(AuthorizationRequest), nameof(AuthorizationRequest.State)).BindModelAsync(context);
        return context;
    }

    /// <summary>A model a host declares itself.</summary>
    public sealed class HostModel
    {
        public string? Name { get; set; }

        public CultureInfo[]? Languages { get; set; }
    }
}
