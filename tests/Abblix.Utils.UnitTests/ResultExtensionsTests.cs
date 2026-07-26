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

namespace Abblix.Utils.UnitTests;

/// <summary>
/// The combinators that lift a plain value into <see cref="Result{TSuccess,TFailure}"/>: a predicate gate and
/// the null check, each in a synchronous and an awaited form.
/// </summary>
/// <remarks>
/// Only the lambda-taking <c>FailIfNull</c> has a call site in this library today. The rest are public members
/// of a published package that are deliberately retained, so they are exercised rather than left to be
/// discovered by whoever calls them first. Both arms of every member are asserted, since a combinator that
/// takes the wrong branch does not fail where it is written: it hands the caller a success that should have
/// been a failure, and the request proceeds on it.
/// </remarks>
public class ResultExtensionsTests
{
    private const string Failure = "refused";

    [Fact]
    public void Ensure_ASatisfiedPredicate_KeepsTheValue()
    {
        var result = "openid".Ensure(scope => scope.Length > 0, Failure);

        Assert.True(result.TryGetSuccess(out var value));
        Assert.Equal("openid", value);
    }

    [Fact]
    public void Ensure_AnUnsatisfiedPredicate_ProducesTheFailure()
    {
        var result = string.Empty.Ensure(scope => scope.Length > 0, Failure);

        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(Failure, failure);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EnsureAsync_AwaitsTheValueThenAppliesThePredicate(bool satisfied)
    {
        var result = await Task.FromResult(satisfied ? "openid" : string.Empty)
            .EnsureAsync(scope => scope.Length > 0, Failure);

        Assert.Equal(satisfied, result.TryGetSuccess(out _));
    }

    [Fact]
    public void FailIfNull_APresentValue_Succeeds()
    {
        var result = "openid".FailIfNull(Failure);

        Assert.True(result.TryGetSuccess(out var value));
        Assert.Equal("openid", value);
    }

    [Fact]
    public void FailIfNull_AnAbsentValue_ProducesTheFailure()
    {
        var result = ((string?)null).FailIfNull(Failure);

        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(Failure, failure);
    }

    /// <summary>
    /// The lambda overload exists so an expensive failure is built only when it is needed. Asserting that it
    /// stays unbuilt on the success path is the whole difference between the two overloads.
    /// </summary>
    [Fact]
    public void FailIfNull_WithALambda_DoesNotBuildTheFailureOnSuccess()
    {
        var built = 0;

        var result = "openid".FailIfNull(() => { built++; return Failure; });

        Assert.True(result.TryGetSuccess(out _));
        Assert.Equal(0, built);
    }

    [Fact]
    public void FailIfNull_WithALambda_BuildsTheFailureOnlyWhenAbsent()
    {
        var built = 0;

        var result = ((string?)null).FailIfNull(() => { built++; return Failure; });

        Assert.True(result.TryGetFailure(out _));
        Assert.Equal(1, built);
    }

    [Theory]
    [InlineData("openid")]
    [InlineData(null)]
    public async Task FailIfNullAsync_AwaitsThenChecks(string? value)
    {
        var result = await Task.FromResult(value).FailIfNullAsync(Failure);

        Assert.Equal(value is not null, result.TryGetSuccess(out _));
    }

    [Theory]
    [InlineData("openid")]
    [InlineData(null)]
    public async Task FailIfNullAsync_WithALambda_AwaitsThenChecks(string? value)
    {
        var result = await Task.FromResult(value).FailIfNullAsync(() => Failure);

        Assert.Equal(value is not null, result.TryGetSuccess(out _));
    }
}
