// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
    private static Result<int, string> Ok(int value = 42) => (Result<int, string>)(value);
    private static Result<int, string> No(string error = "refused") => (Result<int, string>)(error);

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
            42L, Ok().Bind(value => (Result<long, string>)(value)).GetSuccess());

        Assert.Equal(
            "refused", No().Bind(value => (Result<long, string>)(value)).GetFailure());

        // A step that refuses turns the chain into that refusal.
        Assert.Equal("second step said no", Ok().Bind(_ => (Result<long, string>)("second step said no"))
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
            42L,
            (await Ok().BindAsync(value => Task.FromResult((Result<long, string>)(value))))
            .GetSuccess());

        Assert.Equal(
            "refused",
            (await No().BindAsync(value => Task.FromResult((Result<long, string>)(value))))
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

    /// <summary>
    /// The value carrying neither arm, which a union has and the hierarchy it replaced did not.
    /// </summary>
    /// <remarks>
    /// Nothing in the library produces one, so every assertion here is about a value that arrives by
    /// accident: an uninitialised field, a loose mock answering with the default of the return type, or
    /// <c>GetValueOrDefault</c> on a nullable result. Each of those reads as an ordinary result at the
    /// call site, so what the members do with it decides whether the mistake is reported or travels.
    /// <para>
    /// Driven because the type's own documentation says what this state does, and a sentence about a
    /// state no test constructs is a claim rather than a behaviour.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheValueCarryingNeitherArmIsRefusedRatherThanAnswered()
    {
        var neither = default(Result<int, string>);

        // The getters name the state they met, rather than the arm the caller happened to ask for: a
        // message saying "not a failure" sends whoever reads it to audit the failure path. Asserted by
        // what the message must SAY - a pair of "does not contain" passes for an empty message too.
        var onSuccess = Assert.Throws<InvalidOperationException>(() => neither.GetSuccess());
        var onFailure = Assert.Throws<InvalidOperationException>(() => neither.GetFailure());
        Assert.Equal(onSuccess.Message, onFailure.Message);
        Assert.StartsWith(
            "The result carries neither a success nor a failure.", onSuccess.Message, StringComparison.Ordinal);

        Assert.Throws<InvalidOperationException>(() => (int)neither);
        Assert.Throws<InvalidOperationException>(
            () => neither.Match(value => $"ok:{value}", error => $"no:{error}"));
        Assert.Throws<InvalidOperationException>(() => neither.MapSuccess(value => value + 1));
        Assert.Throws<InvalidOperationException>(() => neither.MapFailure(error => error.Length));
        Assert.Throws<InvalidOperationException>(
            () => neither.Bind(value => (Result<long, string>)(value)));
        Assert.Throws<InvalidOperationException>(() => neither.Ensure(value => value > 0, "refused"));

        // The pair that answers a question rather than producing a value says no to both, which is the
        // only answer that is true of a value carrying neither arm.
        Assert.False(neither.TryGetSuccess(out _));
        Assert.False(neither.TryGetFailure(out _));

        var (value, error) = neither;
        Assert.Equal(0, value);
        Assert.Null(error);

        Assert.Equal("a result carrying neither case", neither.ToString());
    }

    /// <summary>
    /// A case built from a null value lands in that same state, rather than in a case whose value is null.
    /// </summary>
    /// <remarks>
    /// The second door into it, and the one a caller can walk through by accident: a union stores its
    /// content as an object and a type pattern does not match null, so there is nothing to tell the two
    /// apart afterwards. Driven because the type documents it, and because a producer that hands null to
    /// the factory is told nothing at the point where it could still be fixed - the refusal arrives at
    /// whoever reads the result.
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ACaseBuiltFromNullIsTheValueCarryingNeitherArm(bool asSuccess)
    {
        var fromNull = asSuccess
            ? (Result<string, string[]>)(string)null!
            : (Result<string, string[]>)(string[])null!;

        Assert.False(fromNull.TryGetSuccess(out _));
        Assert.False(fromNull.TryGetFailure(out _));

        var thrown = Assert.Throws<InvalidOperationException>(() => fromNull.GetSuccess());
        Assert.StartsWith(
            "The result carries neither a success nor a failure.", thrown.Message, StringComparison.Ordinal);
    }
}
