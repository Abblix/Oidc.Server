// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Utils;

/// <summary>
/// The outcome of an operation: either a value of type <typeparamref name="TSuccess"/> or one of type
/// <typeparamref name="TFailure"/>, never both.
/// </summary>
/// <remarks>
/// A union rather than a hierarchy, so that a caller naming both cases is checked by the compiler: a
/// <c>switch</c> over the two case types that forgets one is an error here, where warnings are errors.
/// The pattern applies to the contained value, so a caller writes the case types themselves rather than
/// wrappers around them.
/// <para>
/// The two case types must be DISTINCT for a given instantiation, because a union tells its cases apart
/// by type. Writing <c>Result&lt;string, string&gt;</c> outright does not compile - the conversion from a
/// string would be ambiguous - but the combinators can still FORM one, since a generic instantiation is
/// not checked that way: <c>Result&lt;int, string&gt;.MapSuccess</c> returning a string produces a value
/// on which both accessors answer yes. Choose the failure type so that cannot happen.
/// </para>
/// <para>
/// A union is a struct, so <c>default</c> is a value of this type that carries neither case, and nothing
/// here produces one - the old hierarchy could not express that state at all. A member that must yield a
/// value throws rather than inventing one; the <c>TryGet</c> pair answers <c>false</c> to both questions,
/// deconstruction yields two defaults, and <c>ToString</c> says which state it found.
/// </para>
/// </remarks>
/// <typeparam name="TSuccess">The type of the success value.</typeparam>
/// <typeparam name="TFailure">The type of the failure value.</typeparam>
public union Result<TSuccess, TFailure>(TSuccess, TFailure)
{
    /// <summary>
    /// Creates a successful result with the specified value.
    /// </summary>
    /// <param name="value">The success value.</param>
    /// <returns>A <see cref="Result{TSuccess, TFailure}"/> representing a successful result.</returns>
    public static Result<TSuccess, TFailure> Success(TSuccess value) => value;

    /// <summary>
    /// Creates a failed result with the specified value.
    /// </summary>
    /// <param name="value">The failure value.</param>
    /// <returns>A <see cref="Result{TSuccess, TFailure}"/> representing a failed result.</returns>
    public static Result<TSuccess, TFailure> Failure(TFailure value) => value;

    /// <summary>
    /// Matches the result and invokes the appropriate function depending on whether the result is a success or failure.
    /// </summary>
    /// <typeparam name="T">The return type of the matching functions.</typeparam>
    /// <param name="onSuccess">The function to invoke if the result is a success.</param>
    /// <param name="onFailure">The function to invoke if the result is a failure.</param>
    /// <returns>The result of the matching function.</returns>
    /// <remarks>
    /// Matched on <see cref="Value"/> rather than on the union, because a union pattern cannot declare a
    /// variable when the case is a type parameter. The cost is the arm below: inside a generic member the
    /// compiler cannot prove the two parameters cover the value, so exhaustiveness is checked here at run
    /// time. At a call site naming the case types it is checked by the compiler, which is the point.
    /// </remarks>
    public T Match<T>(Func<TSuccess, T> onSuccess, Func<TFailure, T> onFailure)
        => Value switch
        {
            TSuccess success => onSuccess(success),
            TFailure failure => onFailure(failure),
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Asynchronously matches the result and invokes the appropriate function.
    /// </summary>
    /// <typeparam name="T">The return type of the matching functions.</typeparam>
    /// <param name="onSuccess">The asynchronous function to invoke if the result is a success.</param>
    /// <param name="onFailure">The function to invoke if the result is a failure.</param>
    /// <returns>A task representing the result of the matching function.</returns>
    public Task<T> MatchAsync<T>(Func<TSuccess, Task<T>> onSuccess, Func<TFailure, T> onFailure)
        => Value switch
        {
            TSuccess success => onSuccess(success),
            TFailure failure => Task.FromResult(onFailure(failure)),
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Asynchronously matches the result and invokes the appropriate asynchronous function.
    /// </summary>
    /// <typeparam name="T">The return type of the matching functions.</typeparam>
    /// <param name="onSuccess">The asynchronous function to invoke if the result is a success.</param>
    /// <param name="onFailure">The asynchronous function to invoke if the result is a failure.</param>
    /// <returns>A task representing the result of the matching function.</returns>
    public Task<T> MatchAsync<T>(Func<TSuccess, Task<T>> onSuccess, Func<TFailure, Task<T>> onFailure)
        => Value switch
        {
            TSuccess success => onSuccess(success),
            TFailure failure => onFailure(failure),
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Asynchronously maps the success value to a new type, leaving a failure untouched.
    /// </summary>
    /// <typeparam name="T">The type to map the success value to.</typeparam>
    /// <param name="onSuccess">The asynchronous mapping function.</param>
    /// <returns>A task representing the mapped result.</returns>
    public async Task<Result<T, TFailure>> MapSuccessAsync<T>(Func<TSuccess, Task<T>> onSuccess)
        => Value switch
        {
            TSuccess success => await onSuccess(success),
            TFailure failure => failure,
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Maps the success value to a new type, leaving a failure untouched.
    /// </summary>
    /// <typeparam name="T">The type to map the success value to.</typeparam>
    /// <param name="onSuccess">The mapping function.</param>
    /// <returns>The mapped result.</returns>
    public Result<T, TFailure> MapSuccess<T>(Func<TSuccess, T> onSuccess)
        => Value switch
        {
            TSuccess success => onSuccess(success),
            TFailure failure => failure,
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Asynchronously maps the failure value to a new type, leaving a success untouched.
    /// </summary>
    /// <typeparam name="T">The type to map the failure value to.</typeparam>
    /// <param name="onFailure">The asynchronous mapping function.</param>
    /// <returns>A task representing the mapped result.</returns>
    public async Task<Result<TSuccess, T>> MapFailureAsync<T>(Func<TFailure, Task<T>> onFailure)
        => Value switch
        {
            TSuccess success => success,
            TFailure failure => await onFailure(failure),
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Maps the failure value to a new type, leaving a success untouched.
    /// </summary>
    /// <typeparam name="T">The type to map the failure value to.</typeparam>
    /// <param name="onFailure">The mapping function.</param>
    /// <returns>The mapped result.</returns>
    public Result<TSuccess, T> MapFailure<T>(Func<TFailure, T> onFailure)
        => Value switch
        {
            TSuccess success => success,
            TFailure failure => onFailure(failure),
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Maps both success and failure values to new types.
    /// </summary>
    /// <typeparam name="TNewSuccess">The type to map the success value to.</typeparam>
    /// <typeparam name="TNewFailure">The type to map the failure value to.</typeparam>
    /// <param name="onSuccess">The function to apply if the result is successful.</param>
    /// <param name="onFailure">The function to apply if the result is a failure.</param>
    /// <returns>A new result with both success and failure values mapped to new types.</returns>
    public Result<TNewSuccess, TNewFailure> Map<TNewSuccess, TNewFailure>(
        Func<TSuccess, TNewSuccess> onSuccess,
        Func<TFailure, TNewFailure> onFailure)
        => Match(
            success => Result<TNewSuccess, TNewFailure>.Success(onSuccess(success)),
            failure => Result<TNewSuccess, TNewFailure>.Failure(onFailure(failure))
        );

    /// <summary>
    /// Determines whether the result is a success.
    /// </summary>
    /// <param name="value">When this method returns, contains the success value if the result is successful;
    /// otherwise, the default value.</param>
    /// <returns><c>true</c> if the result is a success; otherwise, <c>false</c>.</returns>
    public bool TryGetSuccess([MaybeNullWhen(false)] out TSuccess value)
    {
        if (Value is TSuccess success)
        {
            value = success;
            return true;
        }

        value = default;
        return false;
    }

    /// <summary>
    /// Gets the success value.
    /// </summary>
    /// <returns>The success value.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the result is a failure.</exception>
    public TSuccess GetSuccess()
        => Value switch
        {
            TSuccess success => success,
            TFailure => throw new InvalidOperationException("The result is not a success."),
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Gets the failure value.
    /// </summary>
    /// <returns>The failure value.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the result is a success.</exception>
    public TFailure GetFailure()
        => Value switch
        {
            TFailure failure => failure,
            TSuccess => throw new InvalidOperationException("The result is not a failure."),
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Determines whether the result is a failure.
    /// </summary>
    /// <param name="value">When this method returns, contains the failure value if the result is a failure;
    /// otherwise, the default value.</param>
    /// <returns><c>true</c> if the result is a failure; otherwise, <c>false</c>.</returns>
    public bool TryGetFailure([MaybeNullWhen(false)] out TFailure value)
    {
        if (Value is TFailure failure)
        {
            value = failure;
            return true;
        }

        value = default;
        return false;
    }

    /// <summary>
    /// Binds the result to a function that returns a new result, allowing chaining of operations.
    /// </summary>
    /// <typeparam name="TNext">The type of the success value in the returned result.</typeparam>
    /// <param name="func">The function to apply to the success value.</param>
    /// <returns>The result of applying the function if successful; otherwise, the original failure.</returns>
    public Result<TNext, TFailure> Bind<TNext>(Func<TSuccess, Result<TNext, TFailure>> func)
        => Value switch
        {
            TSuccess success => func(success),
            TFailure failure => failure,
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Executes the specified action if the result is successful, and returns the original result.
    /// </summary>
    /// <param name="action">The action to execute if the result is successful.</param>
    /// <returns>The original result after executing the action if successful; otherwise, the failure result.</returns>
    public Result<TSuccess, TFailure> Bind(Action<TSuccess> action)
    {
        if (Value is TSuccess success)
            action(success);
        else if (Value is not TFailure)
            throw NeitherCase();

        return this;
    }

    /// <summary>
    /// Asynchronously binds the result to a function that returns a new result, allowing chaining of operations.
    /// </summary>
    /// <typeparam name="TNext">The type of the success value in the returned result.</typeparam>
    /// <param name="func">The asynchronous function to apply to the success value.</param>
    /// <returns>A task representing the result of applying the function if successful; otherwise, the original failure.</returns>
    public Task<Result<TNext, TFailure>> BindAsync<TNext>(Func<TSuccess, Task<Result<TNext, TFailure>>> func)
        => Value switch
        {
            TSuccess success => func(success),
            TFailure failure => Task.FromResult<Result<TNext, TFailure>>(failure),
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Asynchronously executes the specified action if the result is successful, and returns the original result.
    /// </summary>
    /// <param name="action">The asynchronous action to execute if the result is successful.</param>
    /// <returns>A task representing the operation, with the original result.</returns>
    public async Task<Result<TSuccess, TFailure>> BindAsync(Func<TSuccess, Task> action)
    {
        if (Value is TSuccess success)
            await action(success);
        else if (Value is not TFailure)
            throw NeitherCase();

        return this;
    }

    /// <summary>
    /// Ensures that the success value satisfies the specified predicate; otherwise, returns a failure result.
    /// </summary>
    /// <param name="predicate">The predicate to evaluate the success value.</param>
    /// <param name="failure">The failure value to return if the predicate is not satisfied.</param>
    /// <returns>The original success result if the predicate is satisfied; otherwise, a failure result.</returns>
    public Result<TSuccess, TFailure> Ensure(Func<TSuccess, bool> predicate, TFailure failure)
        => Value switch
        {
            TSuccess success => predicate(success) ? this : failure,
            TFailure => this,
            _ => throw NeitherCase(),
        };

    /// <summary>
    /// Deconstructs the result into separate success and failure values.
    /// </summary>
    /// <param name="success">The success value if available; otherwise, <c>null</c>.</param>
    /// <param name="failure">The failure value if available; otherwise, <c>null</c>.</param>
    public void Deconstruct(out TSuccess? success, out TFailure? failure)
    {
        success = Value is TSuccess s ? s : default;
        failure = Value is TFailure f ? f : default;
    }

    /// <summary>
    /// Converts the result explicitly to the success value.
    /// </summary>
    /// <param name="result">The result instance.</param>
    /// <returns>The success value.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the result is a failure.</exception>
    public static explicit operator TSuccess(Result<TSuccess, TFailure> result) => result.GetSuccess();

    /// <summary>
    /// The text of whichever value is there, rather than of the result around it.
    /// </summary>
    /// <remarks>
    /// A log line carrying a result should read as the thing that happened, not as a type name with a
    /// payload nested inside it. The record this replaced gave that away; a union does not, so it is
    /// written out.
    /// </remarks>
    /// <returns>The text of the success or failure value, or a description of a result carrying
    /// neither.</returns>
    public override string ToString()
        => Value switch
        {
            TSuccess success => success?.ToString() ?? string.Empty,
            TFailure failure => failure?.ToString() ?? string.Empty,
            _ => "a result carrying neither case",
        };
    /// <summary>
    /// The refusal for a result carrying neither case, which is what <c>default</c> of this type is.
    /// </summary>
    /// <remarks>
    /// Not defensive programming: a struct has a default value whether or not anything means to produce
    /// one, and the alternative to refusing it is answering as though it were a failure, which would put
    /// a failure nobody produced into a caller's hands.
    /// </remarks>
    private static InvalidOperationException NeitherCase()
        => new("The result carries neither a success nor a failure, which is what default(Result<,>) is.");
}
