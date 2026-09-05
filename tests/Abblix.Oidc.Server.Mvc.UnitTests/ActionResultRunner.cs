// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>
/// Runs an <see cref="ActionResult"/> the way MVC does and reports what reached the wire.
/// </summary>
/// <remarks>
/// Inspecting the returned object is not enough here: a header this adapter attaches lives in a decorator that
/// only applies it while executing, so a test that reads the object sees the status and misses the header
/// entirely. Executing also puts the decorator itself under test, which is where the header logic actually is.
/// </remarks>
internal static class ActionResultRunner
{
    /// <summary>What the client would have received: the status line, the headers and the body.</summary>
    internal sealed record Response(int StatusCode, IHeaderDictionary Headers, string Body);

    internal static async Task<Response> RunAsync(ActionResult result)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        // The object results write their body through MVC's output formatters, which only exist once the MVC
        // core services are registered - without them the execution fails on a missing result executor.
        services.AddMvcCore();

        await using var provider = services.BuildServiceProvider();

        var (context, body) = CreateContext(provider);
        await result.ExecuteResultAsync(context);

        return Capture(context, body);
    }

    /// <summary>
    /// Runs a result through the synchronous <see cref="ActionResult.ExecuteResult"/> entry point instead of the
    /// asynchronous one. Only results that write without awaiting can take this path.
    /// </summary>
    internal static Response Run(ActionResult result)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        using var provider = services.BuildServiceProvider();

        var (context, body) = CreateContext(provider);
        result.ExecuteResult(context);

        return Capture(context, body);
    }

    private static (ActionContext Context, MemoryStream Body) CreateContext(IServiceProvider provider)
    {
        var body = new MemoryStream();
        var httpContext = new DefaultHttpContext
        {
            RequestServices = provider,
            Response = { Body = body },
        };

        return (new ActionContext(httpContext, new RouteData(), new ActionDescriptor()), body);
    }

    private static Response Capture(ActionContext context, MemoryStream body)
        => new(
            context.HttpContext.Response.StatusCode,
            context.HttpContext.Response.Headers,
            Encoding.UTF8.GetString(body.ToArray()));
}
