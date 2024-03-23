using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Implements the fetching and processing of authorization request objects, including JWT validation and model binding.
/// </summary>
public class RequestObjectFetcher : IAuthorizationRequestFetcher
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RequestObjectFetcher"/> class.
    /// </summary>
    /// <param name="logger">The logger for logging debug and warning messages.</param>
    /// <param name="jwtValidator">The validator for JSON Web Tokens (JWTs).</param>
    /// <param name="jsonObjectBinder">The binder for converting JSON payloads into AuthorizationRequest objects.</param>
    /// <param name="clientJwksProvider">The provider for client JSON Web Key Sets (JWKS).</param>
    /// <param name="clientInfoProvider">The provider for client information.</param>
    public RequestObjectFetcher(
        ILogger<RequestObjectFetcher> logger,
        IJsonWebTokenValidator jwtValidator,
        IJsonObjectBinder jsonObjectBinder,
        IClientKeysProvider clientJwksProvider,
        IClientInfoProvider clientInfoProvider)
    {
        _logger = logger;
        _jwtValidator = jwtValidator;
        _jsonObjectBinder = jsonObjectBinder;
        _clientJwksProvider = clientJwksProvider;
        _clientInfoProvider = clientInfoProvider;
    }

    private readonly ILogger _logger;
    private readonly IJsonWebTokenValidator _jwtValidator;
    private readonly IJsonObjectBinder _jsonObjectBinder;
    private readonly IClientKeysProvider _clientJwksProvider;
    private readonly IClientInfoProvider _clientInfoProvider;


    /// <summary>
    /// Fetches and processes the authorization request object, validating its JWT and binding its contents to a new
    /// or updated AuthorizationRequest.
    /// </summary>
    /// <param name="request">
    /// The initial authorization request, potentially containing a 'request' parameter with the JWT.
    /// </param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the processed authorization
    /// request or an error.</returns>
    /// <remarks>
    /// This method decodes and validates the JWT included in the 'request' parameter of the authorization request.
    /// If valid, it binds the JWT payload to the authorization request model. If the JWT is invalid, it logs
    /// a warning and returns an error.
    /// </remarks>
    public async Task<FetchResult> FetchAsync(AuthorizationRequest request)
    {
        if (request is { Request: { } requestObject })
        {
            _logger.LogDebug("JWT request object was: {RequestObject}", requestObject);

            var result = await _jwtValidator.ValidateAsync(
                requestObject,
                new ValidationParameters
                {
                    Options = ValidationOptions.ValidateIssuerSigningKey,
                    ResolveIssuerSigningKeys = ResolveIssuerSigningKeys,
                });

            switch (result)
            {
                case ValidJsonWebToken { Token.Payload.Json: var json }:
                    var updatedRequest = await _jsonObjectBinder.BindModelAsync(json, request);
                    if (updatedRequest == null)
                        return ErrorFactory.InvalidRequestObject($"Unable to bind request object");

                    return updatedRequest;

                case JwtValidationError error:
                    _logger.LogWarning("The request object contains invalid token: {@Error}", error);
                    return ErrorFactory.InvalidRequestObject($"The request object is invalid.");

                default:
                    throw new UnexpectedTypeException(nameof(result), result.GetType());
            }
        }

        return request;
    }

    private async IAsyncEnumerable<JsonWebKey> ResolveIssuerSigningKeys(string clientId)
    {
        var clientInfo = await _clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
        if (clientInfo == null)
            yield break;

        await foreach (var key in _clientJwksProvider.GetSigningKeys(clientInfo))
            yield return key;
    }
}
