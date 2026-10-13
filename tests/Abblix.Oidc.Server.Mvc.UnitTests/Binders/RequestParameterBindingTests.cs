// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using System.Reflection;
using Abblix.Oidc.Server.Mvc.Binders;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using Abblix.Oidc.Server.Mvc.Model;
using AuthorizationRequest = Abblix.Oidc.Server.Mvc.Model.AuthorizationRequest;
using Parameters = Abblix.Oidc.Server.Model.AuthorizationRequest.Parameters;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Binders;

/// <summary>
/// Which parameters the refusal of a repetition and the naming of a value that cannot be read reach, read off the
/// model binder each property of this package's models names, and what the refusal counts.
/// </summary>
public class RequestParameterBindingTests
{
    private static readonly IServiceProvider Services =
        new ServiceCollection().AddLogging().AddOidcMvc().BuildServiceProvider();

    /// <summary>
    /// A query or form parameter of this package's models, whether it binds by default or through a binder of its own,
    /// names the binder that counts it and names an unreadable value.
    /// </summary>
    [Theory]
    [InlineData(nameof(AuthorizationRequest.State))]
    [InlineData(nameof(AuthorizationRequest.RedirectUri))]
    [InlineData(nameof(AuthorizationRequest.UiLocales))]
    [InlineData(nameof(AuthorizationRequest.Claims))]
    [InlineData(nameof(AuthorizationRequest.MaxAge))]
    [InlineData(nameof(AuthorizationRequest.Scope))]
    public void SingleValuedParameterOfThePackageNamesTheParameterBinder(string property)
        => Assert.True(IsParameterBinder(BinderTypeOf(typeof(AuthorizationRequest), property)));

    /// <summary>
    /// A parameter defined as repeatable names the same binder, which leaves it uncounted, and a value of it that
    /// cannot be read is still named.
    /// </summary>
    [Fact]
    public void RepeatableParameterNamesTheParameterBinder()
        => Assert.Equal(
            typeof(RequestParameterBinder),
            BinderTypeOf(typeof(AuthorizationRequest), nameof(AuthorizationRequest.Resources)));

    /// <summary>
    /// A parameter defined as repeatable is bound from every copy rather than refused for being sent twice.
    /// </summary>
    [Fact]
    public async Task RepeatableParameterSentTwiceIsBound()
    {
        var modelState = await BindResourcesAsync(
            "?resource=https://a.example&resource=https://b.example", ModelStateDictionary.DefaultMaxAllowedErrors);

        Assert.Equal(0, modelState.Values.Sum(entry => entry.Errors.Count));
    }

    /// <summary>
    /// A header, the client certificate and a route value bind as they would without this package: only a query or
    /// form parameter is counted.
    /// </summary>
    [Theory]
    [InlineData(typeof(ClientRequest), nameof(ClientRequest.DPoPProof))]
    [InlineData(typeof(ClientRequest), nameof(ClientRequest.AuthorizationHeader))]
    [InlineData(typeof(ClientRequest), nameof(ClientRequest.ClientCertificate))]
    [InlineData(typeof(ClientAuthorizationRequest), nameof(ClientAuthorizationRequest.ClientId))]
    [InlineData(typeof(ClientAuthorizationRequest), nameof(ClientAuthorizationRequest.AuthorizationHeader))]
    public void ParameterOutsideTheQueryAndTheFormIsNotWrapped(Type container, string property)
        => Assert.False(IsParameterBinder(BinderTypeOf(container, property)));

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

    /// <summary>
    /// A value of a repeatable parameter that cannot be read is refused under the parameter's own name, whether it is
    /// sent plainly or under an index, and no failure is left under the indexed key to carry the value.
    /// </summary>
    [Theory]
    [InlineData("?resource=https://[%09")]
    [InlineData("?resource[0]=https://[%09")]
    public async Task UnreadableRepeatableValueIsRefusedUnderTheParameter(string query)
    {
        var modelState = await BindResourcesAsync(query, ModelStateDictionary.DefaultMaxAllowedErrors);

        Assert.Equal(1, modelState.Values.Sum(entry => entry.Errors.Count));
        Assert.Single(modelState[Parameters.Resource]!.Errors);
    }

    /// <summary>
    /// A request carrying as many unreadable values as the model state takes errors still gets the parameter named,
    /// sent with an index or repeated as RFC 8707 clients send it.
    /// </summary>
    [Theory]
    [InlineData("?resource[0]=https://[%09&resource[1]=https://[%09", 2)]
    [InlineData("?resource=https://[%09&resource=https://[%09&resource=https://[%09", 3)]
    public async Task UnreadableValuesUpToTheErrorLimitAreStillRefusedUnderTheParameter(
        string query,
        int maxAllowedErrors)
    {
        var modelState = await BindResourcesAsync(query, maxAllowedErrors);

        Assert.Single(modelState[Parameters.Resource]!.Errors);
    }

    private static Type? BinderTypeOf(Type container, string property)
        => container.GetProperty(property)!.GetCustomAttribute<ModelBinderAttribute>()?.BinderType;

    private static bool IsParameterBinder(Type? binderType)
        => binderType == typeof(RequestParameterBinder)
           || binderType is { IsGenericType: true } && binderType.GetGenericTypeDefinition() == typeof(CustomParameterBinder<>);

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

    private static async Task<ModelStateDictionary> BindResourcesAsync(
        string query,
        int maxAllowedErrors)
    {
        var httpContext = new DefaultHttpContext { RequestServices = Services };
        httpContext.Request.QueryString = new QueryString(query);

        var actionContext = new ActionContext(
            httpContext, new RouteData(), new ActionDescriptor(), new ModelStateDictionary(maxAllowedErrors));
        var valueProvider = new CompositeValueProvider(
        [
            new FormValueProvider(BindingSource.Form, FormCollection.Empty, CultureInfo.InvariantCulture),
            new QueryStringValueProvider(BindingSource.Query, httpContext.Request.Query, CultureInfo.InvariantCulture),
        ]);

        var context = new DefaultModelBindingContext
        {
            ActionContext = actionContext,
            ModelMetadata = Services.GetRequiredService<IModelMetadataProvider>()
                .GetMetadataForProperty(typeof(AuthorizationRequest), nameof(AuthorizationRequest.Resources)),
            FieldName = nameof(AuthorizationRequest.Resources),
            ModelName = Parameters.Resource,
            ModelState = actionContext.ModelState,
            ValueProvider = valueProvider,
        };

        await BinderFor(typeof(AuthorizationRequest), nameof(AuthorizationRequest.Resources)).BindModelAsync(context);
        return context.ModelState;
    }
}
