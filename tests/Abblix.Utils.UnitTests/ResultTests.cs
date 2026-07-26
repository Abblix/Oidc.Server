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
/// The two arms of <see cref="Result{TSuccess,TFailure}"/>, member by member.
/// </summary>
/// <remarks>
/// This type carries every protocol decision the server makes - a request is honoured or refused, and the
/// refusal travels back as the failure arm rather than as an exception. It had no tests of its own: what
/// coverage it showed came from the server exercising it in passing, which proves the paths that server
/// happens to take and says nothing about the rest of the surface a consumer may call.
///
/// Every member below is asserted on both arms, because success and failure are two separate
/// implementations of the same abstract member. A member that is right on one and wrong on the other reads
/// as covered from a single call, and the wrong half is the one that only runs when something has already
/// gone wrong - which is the worst moment to discover it.
/// </remarks>
public class ResultTests
{
    private static Result<int, string> Ok(int value = 42) => Result<int, string>.Success(value);
    private static Result<int, string> No(string error = "refused") => Result<int, string>.Failure(error);

    [Fact]
    public void SuccessAndFailureAreTellable()
    {
        Assert.True(Ok().TryGetSuccess(out var value));
        Assert.Equal(42, value);
        Assert.False(Ok().TryGetFailure(out _));

        Assert.True(No().TryGetFailure(out var error));
        Assert.Equal("refused", error);
        Assert.False(No().TryGetSuccess(out _));
    }

    /// <summary>
    /// A value or an error becomes a result without being wrapped by hand, which is what lets a method
    /// body <c>return</c> either one.
    /// </summary>
    [Fact]
    public void AValueOrAnErrorConvertsOnItsOwn()
    {
        Result<int, string> fromValue = 7;
        Result<int, string> fromError = "denied";

        Assert.True(fromValue.TryGetSuccess(out var value));
        Assert.Equal(7, value);
        Assert.True(fromError.TryGetFailure(out var error));
        Assert.Equal("denied", error);
    }

    /// <summary>
    /// Reading the arm that is not there is a programming mistake, not a value, so it throws rather than
    /// answering with a default that would travel on as if it meant something.
    /// </summary>
    [Fact]
    public void ReadingTheOtherArmThrows()
    {
        Assert.Equal(42, Ok().GetSuccess());
        Assert.Throws<InvalidOperationException>(() => Ok().GetFailure());

        Assert.Equal("refused", No().GetFailure());
        Assert.Throws<InvalidOperationException>(() => No().GetSuccess());
    }

    [Fact]
    public void TheExplicitConversionIsTheSuccessValue()
    {
        Assert.Equal(42, (int)Ok());
        Assert.Throws<InvalidOperationException>(() => (int)No());
    }

    [Fact]
    public void MatchPicksTheArmThatIsThere()
    {
        Assert.Equal("ok:42", Ok().Match(value => $"ok:{value}", error => $"no:{error}"));
        Assert.Equal("no:refused", No().Match(value => $"ok:{value}", error => $"no:{error}"));
    }

    [Fact]
    public async Task MatchAsyncPicksTheArmThatIsThere_WithASynchronousFailureArm()
    {
        Assert.Equal(
            "ok:42",
            await Ok().MatchAsync(value => Task.FromResult($"ok:{value}"), error => $"no:{error}"));

        Assert.Equal(
            "no:refused",
            await No().MatchAsync(value => Task.FromResult($"ok:{value}"), error => $"no:{error}"));
    }

    [Fact]
    public async Task MatchAsyncPicksTheArmThatIsThere_WithBothArmsAsynchronous()
    {
        Assert.Equal(
            "ok:42",
            await Ok().MatchAsync(
                value => Task.FromResult($"ok:{value}"), error => Task.FromResult($"no:{error}")));

        Assert.Equal(
            "no:refused",
            await No().MatchAsync(
                value => Task.FromResult($"ok:{value}"), error => Task.FromResult($"no:{error}")));
    }

    /// <summary>
    /// Mapping one arm leaves the other alone. That is the whole point: a pipeline transforms the value it
    /// is carrying and a refusal travels through it untouched, arriving as the refusal that was made.
    /// </summary>
    [Fact]
    public void MappingOneArmLeavesTheOther()
    {
        Assert.Equal(84, Ok().MapSuccess(value => value * 2).GetSuccess());
        Assert.Equal("refused", No().MapSuccess(value => value * 2).GetFailure());

        Assert.Equal("REFUSED", No().MapFailure(error => error.ToUpperInvariant()).GetFailure());
        Assert.Equal(42, Ok().MapFailure(error => error.ToUpperInvariant()).GetSuccess());
    }

    [Fact]
    public async Task MappingOneArmLeavesTheOther_Asynchronously()
    {
        Assert.Equal(84, (await Ok().MapSuccessAsync(value => Task.FromResult(value * 2))).GetSuccess());
        Assert.Equal(
            "refused", (await No().MapSuccessAsync(value => Task.FromResult(value * 2))).GetFailure());

        Assert.Equal(
            "REFUSED",
            (await No().MapFailureAsync(error => Task.FromResult(error.ToUpperInvariant()))).GetFailure());
        Assert.Equal(
            42, (await Ok().MapFailureAsync(error => Task.FromResult(error.ToUpperInvariant()))).GetSuccess());
    }

    [Fact]
    public void MapTransformsWhicheverArmIsThere()
    {
        var mappedSuccess = Ok().Map(value => value.ToString(), error => error.Length);
        Assert.Equal("42", mappedSuccess.GetSuccess());

        var mappedFailure = No().Map(value => value.ToString(), error => error.Length);
        Assert.Equal("refused".Length, mappedFailure.GetFailure());
    }

    /// <summary>
    /// Binding continues the chain on success and stops it on failure, which is what keeps a caller from
    /// having to ask after every step whether it is still worth continuing.
    /// </summary>
    [Fact]
    public void BindContinuesOnSuccessAndStopsOnFailure()
    {
        Assert.Equal(
            "42", Ok().Bind(value => Result<string, string>.Success(value.ToString())).GetSuccess());

        Assert.Equal(
            "refused", No().Bind(value => Result<string, string>.Success(value.ToString())).GetFailure());

        // A step that refuses turns the chain into that refusal.
        Assert.Equal("second step said no", Ok().Bind(_ => Result<string, string>.Failure("second step said no"))
            .GetFailure());
    }

    [Fact]
    public void BindingAnActionRunsItOnlyOnSuccess()
    {
        var ran = 0;

        Assert.Equal(42, Ok().Bind(_ => ran++).GetSuccess());
        Assert.Equal(1, ran);

        Assert.Equal("refused", No().Bind(_ => ran++).GetFailure());
        Assert.Equal(1, ran);
    }

    [Fact]
    public async Task BindingAsynchronouslyContinuesOnSuccessAndStopsOnFailure()
    {
        Assert.Equal(
            "42",
            (await Ok().BindAsync(value => Task.FromResult(Result<string, string>.Success(value.ToString()))))
            .GetSuccess());

        Assert.Equal(
            "refused",
            (await No().BindAsync(value => Task.FromResult(Result<string, string>.Success(value.ToString()))))
            .GetFailure());
    }

    [Fact]
    public async Task BindingAnAsynchronousActionRunsItOnlyOnSuccess()
    {
        var ran = 0;

        Assert.Equal(42, (await Ok().BindAsync(_ => { ran++; return Task.CompletedTask; })).GetSuccess());
        Assert.Equal(1, ran);

        Assert.Equal("refused", (await No().BindAsync(_ => { ran++; return Task.CompletedTask; })).GetFailure());
        Assert.Equal(1, ran);
    }

    /// <summary>
    /// Ensure turns a condition on the carried value into a refusal, and leaves an existing refusal as it
    /// is rather than replacing it with the new one.
    /// </summary>
    [Fact]
    public void EnsureRefusesOnlyWhatItIsGiven()
    {
        Assert.Equal(42, Ok().Ensure(value => value > 0, "not positive").GetSuccess());
        Assert.Equal("not positive", Ok().Ensure(value => value < 0, "not positive").GetFailure());

        // The first refusal is the one that happened; the predicate never sees a value to judge.
        Assert.Equal("refused", No().Ensure(value => value < 0, "not positive").GetFailure());
    }

    [Fact]
    public void DeconstructionYieldsTheArmThatIsThere()
    {
        var (successValue, successError) = Ok();
        Assert.Equal(42, successValue);
        Assert.Null(successError);

        var (failureValue, failureError) = No();
        Assert.Equal(default, failureValue);
        Assert.Equal("refused", failureError);
    }

    [Fact]
    public void ToStringSpeaksForWhicheverArmIsThere()
    {
        Assert.Equal("42", Ok().ToString());
        Assert.Equal("refused", No().ToString());
    }
}
