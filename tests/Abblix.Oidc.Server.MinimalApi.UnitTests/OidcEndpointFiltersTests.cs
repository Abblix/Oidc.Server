// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// The order of the filters every OpenID endpoint of the Minimal API transport runs behind.
/// </summary>
public sealed class OidcEndpointFiltersTests
{
    private const string ProbePath = "/probe";

    /// <summary>
    /// A request over http to a server serving its one tenant at an http issuer, arriving while the tenant is still
    /// being loaded, waits for the load before the HTTPS requirement judges it: that requirement reads the tenant to
    /// allow an issuer over http, so judged earlier it would redirect a request it lets through once the tenant is
    /// loaded.
    /// </summary>
    [Fact]
    public async Task ARequestOverHttpDuringTheFirstLoad_WaitsBeforeTheHttpsRequirement()
    {
        var preparation = new HeldPreparation();
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(options =>
        {
            options.AllowHttpIssuer = true;
            options.Tenants.Add(new TenantDefinition
            {
                Id = "acme",
                Issuer = new Uri("http://auth.example.com"),
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
            });
        });
        builder.Services.AddSingleton<ITenantOpening>(preparation);
        await using var app = builder.Build();
        app.MapGroup(string.Empty).AddOidcEndpointFilters().MapGet(ProbePath, () => Results.Ok());

        var probe = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>()
            .Single(endpoint => endpoint.RoutePattern.RawText == ProbePath);

        await using var scope = app.Services.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Method = HttpMethods.Get;
        context.Request.Scheme = Uri.UriSchemeHttp;
        context.Request.Host = new HostString("auth.example.com");
        context.Request.Path = ProbePath;
        app.Services.GetRequiredService<IHttpContextAccessor>().HttpContext = context;

        var handled = probe.RequestDelegate!(context);
        Assert.False(handled.IsCompleted);
        await preparation.Started.Task.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);

        preparation.Proceed.SetResult();
        await handled;
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    /// <summary>
    /// A preparation of the tenants that holds their load open until the test releases it.
    /// </summary>
    private sealed class HeldPreparation : ITenantOpening
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Proceed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
            IReadOnlyCollection<TenantDefinition> tenants,
            CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            await Proceed.Task;
            return new Dictionary<string, Exception>();
        }
    }
}
