// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// The conformance host on the Minimal API adapter; everything else it is lives in Abblix.Oidc.Server.Conformance.TestHost

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.AspNetCore.Formatters;
using Abblix.Oidc.Server.Conformance.TestHost;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;

var builder = WebApplication.CreateBuilder(args);

var conformancePages = await ConformanceHost.ConfigureAsync(builder, options => builder.Services.AddOidcServices(options));
builder.Services.Decorate<IEndSessionResponseFormatter<IResult>, MinimalApiEndSessionPages>();

var app = builder.Build();

app.UseRouting();
app.UseCors();
app.UseAuthorization();
app.MapOidcEndpoints();
conformancePages.MapTo(app);

await app.RunAsync();
