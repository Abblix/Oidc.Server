// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using System.Runtime.CompilerServices;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Filters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.Mvc.UnitTests.ActionResults;

/// <summary>
/// Every response this adapter produces for an error keeps the body the library chose, including the empty
/// one.
/// </summary>
/// <remarks>
/// The controllers of this adapter are marked as APIs, and the framework replaces any result it recognizes as
/// a client error with a problem document of its own. A status result is exactly that, so a refusal built
/// from one reaches the caller with a body the library never wrote, while the Minimal API adapter sends the
/// status alone - and the two adapters answer the same request. The caller refusal, the registration-size
/// refusal and the key custodian's each shipped that way and were each found on their own, so what is
/// checked here is the property rather than the site: no result leaving the formatter or the refusal filter
/// may be one the framework can attach a body to. Most of what it enumerates is safe by construction - an
/// error that states itself in the body is an object result, and a status wrapped for a header is not a
/// client error either - so what the enumeration buys is that a new refusal written the wrong way is caught
/// wherever it is added, not that every input here could fail.
/// </remarks>
public class RefusalsCarryNoSynthesizedBodyTests
{
    private const string Realm = "test-realm";

    private static readonly string[] DPoPAlgs = [SigningAlgorithms.RS256];

    /// <summary>
    /// Every error code this library publishes, through both ways an endpoint formats an error and every
    /// fallback status the adapter formats with, since the arm taken depends on all three.
    /// </summary>
    [Fact]
    public void NoFormattedError_IsAResultTheFrameworkWouldGiveABody()
    {
        var codes = typeof(ErrorCodes)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field is { IsLiteral: true, IsInitOnly: false })
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToArray();

        Assert.NotEmpty(codes);

        foreach (var code in codes)
        {
            AssertNoSynthesizedBody(new OidcError(code, "description"), code);
        }
    }

    /// <summary>
    /// And every shape of error the library declares, because the formatter tells some of them apart by type
    /// rather than by code.
    /// </summary>
    [Fact]
    public void NoErrorShape_IsAResultTheFrameworkWouldGiveABody()
    {
        var shapes = typeof(OidcError).Assembly
            .GetTypes()
            .Where(type => typeof(OidcError).IsAssignableFrom(type) && type is { IsAbstract: false })
            .ToArray();

        Assert.NotEmpty(shapes);

        foreach (var shape in shapes)
        {
            // Built without a constructor on purpose: what decides the arm is the type, and a shape whose
            // constructor this test could not satisfy would otherwise leave the population quietly smaller.
            var error = (OidcError)RuntimeHelpers.GetUninitializedObject(shape);
            AssertNoSynthesizedBody(error, shape.Name);
        }

        // The one shape whose arm depends on a value it carries rather than on its type.
        AssertNoSynthesizedBody(new TooManyRequestsError("too many", TimeSpan.FromSeconds(1)), "with an interval");
        AssertNoSynthesizedBody(new TooManyRequestsError("too many", RetryAfter: null), "naming no interval");
    }

    /// <summary>
    /// And every refusal the library raises as an exception, discovered by running the filter over every
    /// exception these assemblies declare and keeping the ones it answers.
    /// </summary>
    [Fact]
    public void NoRefusalTheFilterAnswers_IsAResultTheFrameworkWouldGiveABody()
    {
        var exceptions = new[] { typeof(OidcError).Assembly, typeof(JsonWebToken).Assembly }
            .SelectMany(assembly => assembly.GetTypes())
            .Where(type => typeof(Exception).IsAssignableFrom(type) && type is { IsAbstract: false })
            .ToArray();

        Assert.NotEmpty(exceptions);

        var answered = 0;
        foreach (var type in exceptions)
        {
            var context = ExceptionContextFor((Exception)RuntimeHelpers.GetUninitializedObject(type));

            new ReturnsLibraryRefusalStatusAttribute().OnException(context);
            if (context.Result is not { } result)
                continue;

            answered++;
            Assert.False(
                result is IClientErrorActionResult,
                $"the refusal for {type.Name} would come back with a body the library never wrote");
        }

        // The filter answers something, so a run that found nothing to check fails rather than passing.
        Assert.NotEqual(0, answered);
    }

    private static void AssertNoSynthesizedBody(OidcError error, string what)
    {
        // The three an endpoint of this adapter passes: a request refused, a caller unauthenticated, and a
        // client that was not found, which is the one that reaches the arm the other two step over.
        var fallbacks = new[]
        {
            StatusCodes.Status400BadRequest,
            StatusCodes.Status401Unauthorized,
            StatusCodes.Status404NotFound,
        };

        foreach (var fallback in fallbacks)
        {
            Assert.False(
                error.Format(fallback, Realm) is IClientErrorActionResult,
                $"{what} would come back with a body the library never wrote");

            Assert.False(
                error.Format(fallback, Realm, DPoPAlgs, advertiseBearer: true) is IClientErrorActionResult,
                $"{what} would come back with a body the library never wrote, under the DPoP overload");
        }
    }

    private static ExceptionContext ExceptionContextFor(Exception exception)
        => new(
            new ActionContext(new DefaultHttpContext(), new RouteData(), new ActionDescriptor()),
            [])
        {
            Exception = exception,
        };
}
