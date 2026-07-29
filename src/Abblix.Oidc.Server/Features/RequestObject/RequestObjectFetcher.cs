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

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.RequestObject;

/// <summary>
/// Provides functionality to validate and process JWT request objects, binding their payloads to a request model.
/// This class is typically used in OpenID Connect flows where request parameters are passed as JWTs.
/// </summary>
/// <param name="logger">The logger for recording debug information and warnings.</param>
/// <param name="jsonObjectBinder">The binder for converting JSON payloads into request objects.</param>
/// <param name="serviceProvider">The service provider used for resolving dependencies at runtime.</param>
/// <param name="options">Options that define how request object validation is handled, including whether
/// request objects must be signed.</param>
public partial class RequestObjectFetcher(
    ILogger<RequestObjectFetcher> logger,
    IJsonObjectBinder jsonObjectBinder,
    IServiceProvider serviceProvider,
    IOptionsSnapshot<OidcOptions> options) : IRequestObjectFetcher
{
    /// <summary>
    /// Fetches and processes the request object by validating its JWT and binding the payload to the request model.
    /// </summary>
    /// <typeparam name="T">The type of the request model.</typeparam>
    /// <param name="request">The initial request model to bind the JWT payload to.</param>
    /// <param name="requestObject">The JWT contained within the request, if any.</param>
    /// <param name="requiredSigningAlgorithm">An optional selector returning the signing algorithm the
    /// request object must use for a given client, or <c>null</c> to impose no per-client requirement.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains an <see cref="Result{T, AuthError}"/>
    /// which either represents a successfully processed request or an error indicating issues with the JWT validation.
    /// </returns>
    /// <remarks>
    /// This method is used to decode and validate the JWT contained in the request. If the JWT is valid, the payload
    /// is bound to the request model. If the JWT is invalid, an error is returned and logged.
    /// </remarks>
    public async Task<Result<T, OidcError>> FetchAsync<T>(
        T request,
        string? requestObject,
        Func<ClientInfo, string?>? requiredSigningAlgorithm = null)
        where T : class
    {
        if (!requestObject.HasValue())
            return request;

        var validationResult = await ValidateAsync(requestObject, requiredSigningAlgorithm);
        return await validationResult.BindAsync<T>(
            async validated =>
            {
                var (payload, client) = validated;

                // Strict RFC 9101 §6.3 processing — only the request object's parameters are used and anything
                // passed outside it is ignored — applies when the host turns it on globally or the client's
                // security profile (FAPI 2.0) mandates it. Otherwise the OpenID Connect Core §6.1 merge
                // semantics bind the payload over the outer request. The OAuth-syntax client_id/response_type
                // duplicates are cross-checked against the result by the authorization-endpoint adapter in both.
                var strict = options.Value.IgnoreParametersOutsideRequestObject
                    || SecurityProfileRequirements.For(client, options.Value.DefaultSecurityProfile)
                        .RequireStrictRequestObjectProcessing;
                var target = strict ? Activator.CreateInstance<T>() : request;

                var updatedRequest = await jsonObjectBinder.BindModelAsync(payload, target);
                if (updatedRequest == null)
                    return InvalidRequestObject("Unable to bind request object");

                if (strict)
                    WarnAboutIgnoredOutsideParameters(request, requestObject, payload);

                return updatedRequest;
            }
        );
    }

    /// <summary>
    /// In strict mode (RFC 9101 §6.3) parameters passed outside the request object are silently dropped.
    /// This surfaces them as a warning so an operator can see a client sending parameters that never take
    /// effect. A parameter is reported only when it is absent from the object, is not the parameter that
    /// carries the object itself, and differs from the request model's default (so it was actually supplied).
    /// </summary>
    private void WarnAboutIgnoredOutsideParameters<T>(T request, string? requestObject, JsonObject payload)
        where T : class
    {
        var outer = JsonSerializer.SerializeToNode(request)?.AsObject();
        if (outer is null)
            return;

        var defaults = JsonSerializer.SerializeToNode(Activator.CreateInstance<T>())?.AsObject();

        var ignored = new List<string>();
        foreach (var (name, value) in outer)
        {
            // Carried by the object as well — used, not dropped.
            if (payload.ContainsKey(name))
                continue;

            // The parameter that carries the request object itself is expected to be outside it.
            if (value?.GetValueKind() == JsonValueKind.String && value.GetValue<string>() == requestObject)
                continue;

            // Left at its type default — the client did not actually supply it.
            if (JsonNode.DeepEquals(value, defaults?[name]))
                continue;

            ignored.Add(name);
        }

        if (ignored.Count > 0)
            LogParametersOutsideRequestObjectIgnored(string.Join(", ", ignored));
    }

    /// <summary>
    /// Validates the JWT request object to ensure it complies with the required signing algorithm
    /// and structure, based on the OIDC options.
    /// </summary>
    /// <param name="requestObject">The JWT request object to be validated.</param>
    /// <param name="requiredSigningAlgorithm">An optional selector returning the signing algorithm the
    /// request object must use for a given client, or <c>null</c> to impose no per-client requirement.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a <see cref="Result{JsonObject, AuthError}"/>
    /// indicating whether the JWT is valid or contains errors.
    /// </returns>
    /// <remarks>
    /// This method uses the configured OIDC options to determine whether the JWT must be signed and validates
    /// it accordingly. It retrieves a validator service from the DI container to perform the validation.
    /// </remarks>
    private async Task<Result<(JsonObject Payload, ClientInfo Client), OidcError>> ValidateAsync(
        string requestObject,
        Func<ClientInfo, string?>? requiredSigningAlgorithm)
    {
        // Always validate issuer when present (but accept missing issuer)
        // Always validate signatures when present (ValidateIssuerSigningKey)
        // Always validate lifetime (exp/nbf claims) if present
        // RFC 9101 §4 / OIDC Core §6.1: the aud of a request object SHOULD be the OP — when the
        // object carries an audience, reject values addressed to another server (a request object
        // minted for a different OP must not be replayable here); an absent aud stays accepted.
        // Only require signed tokens when RequireSignedRequestObject is true
        var validationOptions = ValidationOptions.ValidateIssuer |
                                ValidationOptions.ValidateIssuerSigningKey |
                                ValidationOptions.ValidateLifetime |
                                ValidationOptions.ValidateAudience;

        if (options.Value.RequireSignedRequestObject)
            validationOptions |= ValidationOptions.RequireSignedTokens;

        using var scope = serviceProvider.CreateScope();
        var tokenValidator = scope.ServiceProvider.GetRequiredService<IClientJwtValidator>();
        var result = await tokenValidator.ValidateAsync(requestObject, validationOptions);

        return result.Match<Result<(JsonObject Payload, ClientInfo Client), OidcError>>(
            validJwt =>
            {
                // A request object carries authorization request parameters; it is not a token. RFC 9101 §4
                // names its media type as "application/oauth-authz-req+jwt" while noting that "some existing
                // deployments may alternatively be using the type application/jwt", so the exact value cannot
                // be demanded of a conformant client. What can be refused is a JWT declaring itself one of
                // this server's own token classes, which is a token being replayed where request parameters
                // belong - the confusion RFC 8725 §3.11 describes.
                var tokenType = validJwt.Token.Header.Type;
                if (JwtTypes.IsTokenClass(tokenType))
                {
                    return new OidcError(
                        ErrorCodes.InvalidRequestObject,
                        $"A token of type '{tokenType}' cannot be used as a request object");
                }

                // RFC 9101 §10.5: a client registered with require_signed_request_object committed
                // to SIGNED request objects — an unsigned (alg=none) object satisfies the
                // structural check but not the commitment.
                if (validJwt.Client.RequireSignedRequestObject &&
                    string.Equals(validJwt.Token.Header.Algorithm, SigningAlgorithms.None, StringComparison.Ordinal))
                {
                    return new OidcError(
                        ErrorCodes.InvalidRequestObject,
                        "The client is required to sign its request objects");
                }

                // Pin the request object's alg to what the resolved client registered for this
                // request-object kind. The signature is already verified; this rejects a request
                // object signed with a different (e.g. weaker) algorithm than the client registered.
                var requiredAlgorithm = requiredSigningAlgorithm?.Invoke(validJwt.Client);
                if (requiredAlgorithm.HasValue() &&
                    !string.Equals(validJwt.Token.Header.Algorithm, requiredAlgorithm, StringComparison.Ordinal))
                {
                    LogSigningAlgorithmMismatch(
                        validJwt.Client.ClientId, validJwt.Token.Header.Algorithm, requiredAlgorithm);
                    return new OidcError(
                        ErrorCodes.InvalidRequestObject,
                        "The request object signing algorithm does not match the client's registered algorithm");
                }

                return (validJwt.Token.Payload.Json, validJwt.Client);
            },
            error => InvalidRequestObject(error));
    }

    private OidcError InvalidRequestObject(JwtValidationError error)
    {
        LogInvalidToken(error);
        return new OidcError(ErrorCodes.InvalidRequestObject, "The request object is invalid.");
    }

    private static OidcError InvalidRequestObject(string description)
        => new(ErrorCodes.InvalidRequestObject, description);
}
