using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Fetches pushed authorization request objects identified by a URN (Uniform Resource Name) from a storage system.
/// </summary>
public class PushedRequestFetcher : IAuthorizationRequestFetcher
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PushedRequestFetcher"/> class.
    /// </summary>
    /// <param name="authorizationRequestStorage">The storage system used to retrieve pushed authorization
    /// request objects.</param>
    public PushedRequestFetcher(IAuthorizationRequestStorage authorizationRequestStorage)
    {
        _authorizationRequestStorage = authorizationRequestStorage;
    }

    private readonly IAuthorizationRequestStorage _authorizationRequestStorage;

    /// <summary>
    /// Asynchronously retrieves the pushed authorization request object associated with the specified URN.
    /// </summary>
    /// <param name="request">
    /// The authorization request containing a URN from which to fetch the stored pushed authorization request object.
    /// </param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains the fetched pushed authorization
    /// request object or an error if not found.</returns>
    /// <remarks>
    /// This method checks if the provided authorization request contains a URN that references a pushed authorization
    /// request stored in the system. If the URN is valid and corresponds to a stored request, the method retrieves
    /// and returns the request object. If the request object cannot be found or the URN is invalid,
    /// an error is returned.
    /// </remarks>
    public async Task<FetchResult> FetchAsync(AuthorizationRequest request)
    {
        if (request is { RequestUri: { } requestUrn } &&
            requestUrn.OriginalString.StartsWith(RequestUrn.Prefix))
        {
            var requestObject = await _authorizationRequestStorage.TryGetAsync(requestUrn, true);
            return requestObject switch
            {
                null => ErrorFactory.InvalidRequestUri($"Can't find a request by {requestUrn}"),
                _ => requestObject,
            };
        }

        return request;
    }
}
