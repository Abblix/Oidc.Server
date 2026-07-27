// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
