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

namespace Abblix.Utils;

/// <summary>
/// Represents a result of an operation that can either succeed with a value of type <typeparamref name="TSuccess"/>
/// or fail with a value of type <typeparamref name="TFailure"/>.
/// </summary>
/// <typeparam name="TSuccess">The type of the success result.</typeparam>
/// <typeparam name="TFailure">The type of the failure result.</typeparam>
public abstract record Result<TSuccess, TFailure>
{
    private Result() { }

    /// <summary>
    /// Creates a successful result with the specified value.
    /// </summary>
    /// <param name="value">The success value.</param>
    /// <returns>A <see cref="Result{TSuccess, TFailure}"/> representing a successful result.</returns>
    public static Result<TSuccess, TFailure> Success(TSuccess value) => new SuccessResult(value);

    /// <summary>
    /// Creates a failed result with the specified value.
    /// </summary>
    /// <param name="value">The failure value.</param>
    /// <returns>A <see cref="Result{TSuccess, TFailure}"/> representing a failed result.</returns>
    public static Result<TSuccess, TFailure> Failure(TFailure value) => new FailureResult(value);


    /// <summary>
    /// Implicitly converts a value of type <typeparamref name="TSuccess"/> to a successful result.
    /// </summary>
    /// <param name="value">The success value.</param>
    public static implicit operator Result<TSuccess, TFailure>(TSuccess value) => Success(value);

    /// <summary>
    /// Implicitly converts a value of type <typeparamref name="TFailure"/> to a failed result.
    /// </summary>
    /// <param name="error">The failure value.</param>
    public static implicit operator Result<TSuccess, TFailure>(TFailure error) => Failure(error);

    /// <summary>
    /// Matches the result and invokes the appropriate function depending on whether the result is a success or failure.
    /// </summary>
    /// <typeparam name="T">The return type of the matching functions.</typeparam>
    /// <param name="onSuccess">The function to invoke if the result is a success.</param>
    /// <param name="onFailure">The function to invoke if the result is a failure.</param>
    /// <returns>The result of the matching function.</returns>
    public abstract T Match<T>(Func<TSuccess, T> onSuccess, Func<TFailure, T> onFailure);

    /// <summary>
    /// Asynchronously matches the result and invokes the appropriate function.
    /// </summary>
    /// <typeparam name="T">The return type of the matching functions.</typeparam>
    /// <param name="onSuccess">The asynchronous function to invoke if the result is a success.</param>
    /// <param name="onFailure">The function to invoke if the result is a failure.</param>
    /// <returns>A task representing the result of the matching function.</returns>
    public abstract Task<T> MatchAsync<T>(Func<TSuccess, Task<T>> onSuccess, Func<TFailure, T> onFailure);

    /// <summary>
    /// Asynchronously matches the result and invokes the appropriate asynchronous function.
    /// </summary>
    /// <typeparam name="T">The return type of the matching functions.</typeparam>
    /// <param name="onSuccess">The asynchronous function to invoke if the result is a success.</param>
    /// <param name="onFailure">The asynchronous function to invoke if the result is a failure.</param>
    /// <returns>A task representing the result of the matching function.</returns>
    public abstract Task<T> MatchAsync<T>(Func<TSuccess, Task<T>> onSuccess, Func<TFailure, Task<T>> onFailure);

    /// <summary>
    /// Asynchronously maps a successful result to another type.
    /// </summary>
    /// <typeparam name="T">The type to map the success value to.</typeparam>
    /// <param name="onSuccess">The asynchronous mapping function.</param>
    /// <returns>A new result with the mapped success value or the original failure.</returns>
    public abstract Task<Result<T, TFailure>> MapSuccessAsync<T>(Func<TSuccess, Task<T>> onSuccess);

    /// <summary>
    /// Synchronously maps a successful result to another type.
    /// </summary>
    /// <typeparam name="T">The type to map the success value to.</typeparam>
    /// <param name="onSuccess">The mapping function.</param>
    /// <returns>A new result with the mapped success value or the original failure.</returns>
    public abstract Result<T, TFailure> MapSuccess<T>(Func<TSuccess, T> onSuccess);

    /// <summary>
    /// Asynchronously maps a failure result to another type.
    /// </summary>
    /// <typeparam name="T">The type to map the failure value to.</typeparam>
    /// <param name="onFailure">The asynchronous mapping function.</param>
    /// <returns>A new result with the mapped failure value or the original success.</returns>
    public abstract Task<Result<TSuccess, T>> MapFailureAsync<T>(Func<TFailure, Task<T>> onFailure);

    /// <summary>
    /// Synchronously maps a failed result to another type.
    /// </summary>
    /// <typeparam name="T">The type to map the failure value to.</typeparam>
    /// <param name="onFailure">The mapping function.</param>
    /// <returns>A new result with the mapped failure value or the original success.</returns>
    public abstract Result<TSuccess, T> MapFailure<T>(Func<TFailure, T> onFailure);

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
    public abstract bool TryGetSuccess(out TSuccess value);

    /// <summary>
    /// Gets the success value.
    /// </summary>
    /// <returns>The success value.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the result is a failure.</exception>
    public abstract TSuccess GetSuccess();

    /// <summary>
    /// Gets the failure value.
    /// </summary>
    /// <returns>The failure value.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the result is a success.</exception>
    public abstract TFailure GetFailure();

    /// <summary>
    /// Determines whether the result is a failure.
    /// </summary>
    /// <param name="value">When this method returns, contains the failure value if the result is a failure;
    /// otherwise, the default value.</param>
    /// <returns><c>true</c> if the result is a failure; otherwise, <c>false</c>.</returns>
    public abstract bool TryGetFailure(out TFailure value);

    /// <summary>
    /// Deconstructs the result into separate success and failure values.
    /// </summary>
    /// <param name="success">The success value if available; otherwise, <c>null</c>.</param>
    /// <param name="failure">The failure value if available; otherwise, <c>null</c>.</param>
    public abstract void Deconstruct(out TSuccess? success, out TFailure? failure);

    /// <summary>
    /// Binds the result to a function that returns a new result, allowing chaining of operations.
    /// </summary>
    /// <typeparam name="TNext">The type of the success value in the returned result.</typeparam>
    /// <param name="func">The function to apply to the success value.</param>
    /// <returns>The result of applying the function if successful; otherwise, the original failure.</returns>
    public abstract Result<TNext, TFailure> Bind<TNext>(Func<TSuccess, Result<TNext, TFailure>> func);

    /// <summary>
    /// Asynchronously binds the result to a function that returns a new result, allowing chaining of operations.
    /// </summary>
    /// <typeparam name="TNext">The type of the success value in the returned result.</typeparam>
    /// <param name="func">The asynchronous function to apply to the success value.</param>
    /// <returns>A task representing the result of applying the function if successful; otherwise, the original failure.</returns>
    public abstract Task<Result<TNext, TFailure>> BindAsync<TNext>(Func<TSuccess, Task<Result<TNext, TFailure>>> func);

    /// <summary>
    /// Ensures that the success value satisfies the specified predicate; otherwise, returns a failure result.
    /// </summary>
    /// <param name="predicate">The predicate to evaluate the success value.</param>
    /// <param name="failure">The failure value to return if the predicate is not satisfied.</param>
    /// <returns>The original success result if the predicate is satisfied; otherwise, a failure result.</returns>
    public abstract Result<TSuccess, TFailure> Ensure(Func<TSuccess, bool> predicate, TFailure failure);

    /// <summary>
    /// Executes the specified action if the result is successful, and returns the original result.
    /// </summary>
    /// <param name="action">The action to execute if the result is successful.</param>
    /// <returns>The original result after executing the action if successful; otherwise, the failure result.</returns>
    public abstract Result<TSuccess, TFailure> Bind(Action<TSuccess> action);

    /// <summary>
    /// Asynchronously executes the specified action if the result is successful, and returns the original result.
    /// </summary>
    /// <param name="action">The asynchronous action to execute if the result is successful.</param>
    /// <returns>A task representing the operation, with the original result.</returns>
    public abstract Task<Result<TSuccess, TFailure>> BindAsync(Func<TSuccess, Task> action);

    /// <summary>
    /// Converts the result explicitly to the success value.
    /// </summary>
    /// <param name="result">The result instance.</param>
    /// <returns>The success value.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the result is a failure.</exception>
    public static explicit operator TSuccess(Result<TSuccess, TFailure> result) => result.GetSuccess();

        /// <summary>
    /// Represents a successful result.
    /// </summary>
    private sealed record SuccessResult : Result<TSuccess, TFailure>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Result{TSuccess,TFailure}.SuccessResult"/>
        /// record with the specified value.
        /// </summary>
        /// <param name="value">The success value.</param>
        public SuccessResult(TSuccess value)
        {
            Value = value;
        }

        /// <summary>The success value.</summary>
        public TSuccess Value { get; }

        /// <inheritdoc />
        public override TSuccess GetSuccess() => Value;

        /// <inheritdoc />
        public override TFailure GetFailure() => throw new InvalidOperationException("The operation was successful");

        /// <inheritdoc />
        public override string ToString() => Value?.ToString() ?? string.Empty;

        /// <summary>
        /// Determines whether the result is a success.
        /// </summary>
        /// <param name="value">When this method returns, contains the success value if the result is successful;
        /// otherwise, the default value.</param>
        /// <returns><c>true</c> if the result is a success; otherwise, <c>false</c>.</returns>
        public override bool TryGetSuccess(out TSuccess value)
        {
            value = Value;
            return true;
        }

        /// <summary>
        /// Determines whether the result is a failure.
        /// </summary>
        /// <param name="value">When this method returns, contains the failure value if the result is a failure;
        /// otherwise, the default value.</param>
        /// <returns><c>true</c> if the result is a failure; otherwise, <c>false</c>.</returns>
        public override bool TryGetFailure(out TFailure value)
        {
            value = default!;
            return false;
        }

        /// <summary>
        /// Matches the result and invokes the appropriate function depending on whether the result is a success or failure.
        /// </summary>
        /// <typeparam name="T">The return type of the matching functions.</typeparam>
        /// <param name="onSuccess">The function to invoke if the result is a success.</param>
        /// <param name="onFailure">The function to invoke if the result is a failure.</param>
        /// <returns>The result of the matching function.</returns>
        public override T Match<T>(Func<TSuccess, T> onSuccess, Func<TFailure, T> onFailure) => onSuccess(Value);

        /// <summary>
        /// Asynchronously matches the result and invokes the appropriate function.
        /// </summary>
        /// <typeparam name="T">The return type of the matching functions.</typeparam>
        /// <param name="onSuccess">The asynchronous function to invoke if the result is a success.</param>
        /// <param name="onFailure">The function to invoke if the result is a failure.</param>
        /// <returns>A task representing the result of the matching function.</returns>
        public override Task<T> MatchAsync<T>(Func<TSuccess, Task<T>> onSuccess, Func<TFailure, T> onFailure)
            => onSuccess(Value);

        /// <summary>
        /// Asynchronously matches the result and invokes the appropriate asynchronous function.
        /// </summary>
        /// <typeparam name="T">The return type of the matching functions.</typeparam>
        /// <param name="onSuccess">The asynchronous function to invoke if the result is a success.</param>
        /// <param name="onFailure">The asynchronous function to invoke if the result is a failure.</param>
        /// <returns>A task representing the result of the matching function.</returns>
        public override Task<T> MatchAsync<T>(Func<TSuccess, Task<T>> onSuccess, Func<TFailure, Task<T>> onFailure)
            => onSuccess(Value);

        /// <summary>
        /// Asynchronously maps a successful result to another type.
        /// </summary>
        /// <typeparam name="T">The type to map the success value to.</typeparam>
        /// <param name="onSuccess">The asynchronous mapping function.</param>
        /// <returns>A new result with the mapped success value or the original failure.</returns>
        public override async Task<Result<T, TFailure>> MapSuccessAsync<T>(Func<TSuccess, Task<T>> onSuccess)
            => await onSuccess(Value);

        /// <summary>
        /// Synchronously maps a successful result to another type.
        /// </summary>
        /// <typeparam name="T">The type to map the success value to.</typeparam>
        /// <param name="onSuccess">The mapping function.</param>
        /// <returns>A new result with the mapped success value or the original failure.</returns>
        public override Result<T, TFailure> MapSuccess<T>(Func<TSuccess, T> onSuccess)
            => onSuccess(Value);

        /// <summary>
        /// Asynchronously maps a failure result to another type.
        /// </summary>
        /// <typeparam name="T">The type to map the failure value to.</typeparam>
        /// <param name="onFailure">The asynchronous mapping function.</param>
        /// <returns>A new result with the mapped failure value or the original success.</returns>
        public override Task<Result<TSuccess, T>> MapFailureAsync<T>(Func<TFailure, Task<T>> onFailure)
            => Task.FromResult<Result<TSuccess, T>>(Value);

        /// <summary>
        /// Synchronously maps a failed result to another type.
        /// </summary>
        /// <typeparam name="T">The type to map the failure value to.</typeparam>
        /// <param name="onFailure">The mapping function.</param>
        /// <returns>A new result with the mapped failure value or the original success.</returns>
        public override Result<TSuccess, T> MapFailure<T>(Func<TFailure, T> onFailure)
            => Value;

        /// <inheritdoc />
        public override Result<TNext, TFailure> Bind<TNext>(Func<TSuccess, Result<TNext, TFailure>> func)
            => func(Value);

        /// <inheritdoc />
        public override Result<TSuccess, TFailure> Bind(Action<TSuccess> action)
        {
            action(Value);
            return this;
        }

        /// <inheritdoc />
        public override async Task<Result<TNext, TFailure>> BindAsync<TNext>(Func<TSuccess, Task<Result<TNext, TFailure>>> func)
            => await func(Value);

        /// <inheritdoc />
        public override async Task<Result<TSuccess, TFailure>> BindAsync(Func<TSuccess, Task> action)
        {
            await action(Value);
            return this;
        }

        /// <inheritdoc />
        public override Result<TSuccess, TFailure> Ensure(Func<TSuccess, bool> predicate, TFailure failure)
            => predicate(Value) ? this : Failure(failure);

        /// <inheritdoc />
        public override void Deconstruct(out TSuccess? success, out TFailure? failure)
        {
            success = Value;
            failure = default;
        }
    }

    /// <summary>
    /// Represents a failed result.
    /// </summary>
    private sealed record FailureResult : Result<TSuccess, TFailure>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Result{TSuccess,TFailure}.FailureResult"/>
        /// record with the specified value.
        /// </summary>
        /// <param name="value">The failure value.</param>
        public FailureResult(TFailure value)
        {
            Value = value;
        }

        /// <summary>The failure value.</summary>
        public TFailure Value { get; }

        /// <inheritdoc />
        public override TSuccess GetSuccess() => throw new InvalidOperationException("The operation was not successful");

        /// <inheritdoc />
        public override TFailure GetFailure() => Value;

        /// <inheritdoc />
        public override string ToString() => Value?.ToString() ?? string.Empty;

        /// <summary>
        /// Determines whether the result is a success.
        /// </summary>
        /// <param name="value">When this method returns, contains the success value if the result is successful;
        /// otherwise, the default value.</param>
        /// <returns><c>true</c> if the result is a success; otherwise, <c>false</c>.</returns>
        public override bool TryGetSuccess(out TSuccess value)
        {
            value = default!;
            return false;
        }

        /// <summary>
        /// Determines whether the result is a failure.
        /// </summary>
        /// <param name="value">When this method returns, contains the failure value if the result is a failure;
        /// otherwise, the default value.</param>
        /// <returns><c>true</c> if the result is a failure; otherwise, <c>false</c>.</returns>
        public override bool TryGetFailure(out TFailure value)
        {
            value = Value;
            return true;
        }

        /// <summary>
        /// Matches the result and invokes the appropriate function depending on whether the result is a success or failure.
        /// </summary>
        /// <typeparam name="T">The return type of the matching functions.</typeparam>
        /// <param name="onSuccess">The function to invoke if the result is a success.</param>
        /// <param name="onFailure">The function to invoke if the result is a failure.</param>
        /// <returns>The result of the matching function.</returns>
        public override T Match<T>(Func<TSuccess, T> onSuccess, Func<TFailure, T> onFailure) => onFailure(Value);

        /// <summary>
        /// Asynchronously matches the result and invokes the appropriate function.
        /// </summary>
        /// <typeparam name="T">The return type of the matching functions.</typeparam>
        /// <param name="onSuccess">The asynchronous function to invoke if the result is a success.</param>
        /// <param name="onFailure">The function to invoke if the result is a failure.</param>
        /// <returns>A task representing the result of the matching function.</returns>
        public override Task<T> MatchAsync<T>(Func<TSuccess, Task<T>> onSuccess, Func<TFailure, T> onFailure)
            => Task.FromResult(onFailure(Value));

        /// <summary>
        /// Asynchronously matches the result and invokes the appropriate asynchronous function.
        /// </summary>
        /// <typeparam name="T">The return type of the matching functions.</typeparam>
        /// <param name="onSuccess">The asynchronous function to invoke if the result is a success.</param>
        /// <param name="onFailure">The asynchronous function to invoke if the result is a failure.</param>
        /// <returns>A task representing the result of the matching function.</returns>
        public override Task<T> MatchAsync<T>(Func<TSuccess, Task<T>> onSuccess, Func<TFailure, Task<T>> onFailure)
            => onFailure(Value);

        /// <summary>
        /// Asynchronously maps a successful result to another type.
        /// </summary>
        /// <typeparam name="T">The type to map the success value to.</typeparam>
        /// <param name="onSuccess">The asynchronous mapping function.</param>
        /// <returns>A new result with the mapped success value or the original failure.</returns>
        public override Task<Result<T, TFailure>> MapSuccessAsync<T>(Func<TSuccess, Task<T>> onSuccess)
            => Task.FromResult<Result<T, TFailure>>(Value);

        /// <summary>
        /// Synchronously maps a successful result to another type.
        /// </summary>
        /// <typeparam name="T">The type to map the success value to.</typeparam>
        /// <param name="onSuccess">The mapping function.</param>
        /// <returns>A new result with the mapped success value or the original failure.</returns>
        public override Result<T, TFailure> MapSuccess<T>(Func<TSuccess, T> onSuccess)
            => Value;

        /// <summary>
        /// Asynchronously maps a failure result to another type.
        /// </summary>
        /// <typeparam name="T">The type to map the failure value to.</typeparam>
        /// <param name="onFailure">The asynchronous mapping function.</param>
        /// <returns>A new result with the mapped failure value or the original success.</returns>
        public override async Task<Result<TSuccess, T>> MapFailureAsync<T>(Func<TFailure, Task<T>> onFailure)
            => await onFailure(Value);

        /// <summary>
        /// Synchronously maps a failed result to another type.
        /// </summary>
        /// <typeparam name="T">The type to map the failure value to.</typeparam>
        /// <param name="onFailure">The mapping function.</param>
        /// <returns>A new result with the mapped failure value or the original success.</returns>
        public override Result<TSuccess, T> MapFailure<T>(Func<TFailure, T> onFailure)
            => onFailure(Value);

        /// <inheritdoc />
        public override Result<TNext, TFailure> Bind<TNext>(Func<TSuccess, Result<TNext, TFailure>> func)
            => Value;

        /// <inheritdoc />
        public override Result<TSuccess, TFailure> Bind(Action<TSuccess> action) => this;

        /// <inheritdoc />
        public override Task<Result<TNext, TFailure>> BindAsync<TNext>(Func<TSuccess, Task<Result<TNext, TFailure>>> func)
            => Task.FromResult<Result<TNext, TFailure>>(Value);

        /// <inheritdoc />
        public override Task<Result<TSuccess, TFailure>> BindAsync(Func<TSuccess, Task> action)
            => Task.FromResult<Result<TSuccess, TFailure>>(this);

        /// <inheritdoc />
        public override Result<TSuccess, TFailure> Ensure(Func<TSuccess, bool> predicate, TFailure failure)
            => this;

        /// <inheritdoc />
        public override void Deconstruct(out TSuccess? success, out TFailure? failure)
        {
            success = default;
            failure = Value;
        }
    }
}
