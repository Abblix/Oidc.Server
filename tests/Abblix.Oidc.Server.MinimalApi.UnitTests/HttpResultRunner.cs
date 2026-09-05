// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// Runs an <see cref="IResult"/> the way the pipeline does and reports what reached the wire.
/// </summary>
/// <remarks>
/// Inspecting the returned object is not enough here: a header this adapter attaches lives in a decorator that
/// only applies it while executing, so a test that reads the object sees the status and misses the header
/// entirely. Executing also puts the decorator itself under test, which is where the header logic actually is.
/// </remarks>
internal static class HttpResultRunner
{
    /// <summary>What the client would have received: the status line, the headers and the body.</summary>
    internal sealed record Response(int StatusCode, IHeaderDictionary Headers, string Body);

    internal static async Task<Response> RunAsync(IResult result)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        await using var provider = services.BuildServiceProvider();

        var body = new MemoryStream();
        var context = new DefaultHttpContext
        {
            RequestServices = provider,
            Response = { Body = body },
        };

        await result.ExecuteAsync(context);

        return new Response(
            context.Response.StatusCode,
            context.Response.Headers,
            Encoding.UTF8.GetString(body.ToArray()));
    }
}
