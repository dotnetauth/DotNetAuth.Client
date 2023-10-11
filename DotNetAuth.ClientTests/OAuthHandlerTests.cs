using NUnit.Framework;
using DotNetAuth.ClientTests.Mocks;
using Moq;
using System.Net;
using Moq.Protected;

namespace DotNetAuth.Client.Tests
{
    [TestFixture]
    public class OAuthHandlerTests
    {
        // Helper method to create a mock ICodeVerifierStore
        private static ICodeVerifierStore CreateMockCodeVerifierStore()
        {
            return new CodeVerifierStoreMock();
        }

        // Helper method to create a mock AuthorizationServerDefinitionBase
        private static AuthorizationServerDefinitionBase CreateMockAuthorizationServerDefinition()
        {
            var mockAuthorizationServerDefinition = new Mock<AuthorizationServerDefinitionBase>();
            mockAuthorizationServerDefinition
                .Setup(def => def.GetAuthorizationRequestParameters(It.IsAny<ClientCredentials>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<AuthorizationSettings>(),  It.IsAny<string?>())).Returns(
                new Dictionary<string, string>
                {
                    { "client_id", "mock_client_id" },
                    { "response_type", "code" }
                }
            );
            mockAuthorizationServerDefinition
                .Setup(def => def.GetAccessTokenRequestParameters(It.IsAny<ClientCredentials>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns(
                    new Dictionary<string, string>
                    {
                        { "code", "mock_code" },
                        { "client_id", "mock_client_id" },
                        { "client_secret", "mock_client_secret" },
                        { "grant_type", "mock_grant_type" }
                    });

            mockAuthorizationServerDefinition
                .Setup(def => def.ParseAccessTokenResult(It.IsAny<string>()))
                .Returns(
                    new AuthorizationSuccessResponse(
                        new Dictionary<string, object?>(),
                            "mock_access_token",
                            "bearer",
                            3600,
                            "mock_refresh_token",
                            "scope1 scope2",
                            DateTime.UtcNow
                        ));
            mockAuthorizationServerDefinition.Setup(def => def.TokenEndpointUri).Returns("https://example.com/token");
            mockAuthorizationServerDefinition.Setup(def => def.AuthorizationEndpointUri).Returns("https://example.com/authorize");
            return mockAuthorizationServerDefinition.Object;
        }

        [Test]
        public void GetAuthorizationUri_ReturnsValidUri()
        {
            // Arrange
            var codeVerifierStoreMock = new Mock<ICodeVerifierStore>();
            var httpClientFactoryMock = new Mock<Func<HttpClient>>();
            var httpResponseMock = new HttpResponseMessage(HttpStatusCode.OK);
            var mockHttpHandler = new Mock<HttpMessageHandler>();
            mockHttpHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                               .ReturnsAsync(httpResponseMock);
            var httpClientMock = new HttpClient(mockHttpHandler.Object);

            httpClientFactoryMock.Setup(f => f()).Returns(httpClientMock);

            codeVerifierStoreMock.Setup(c => c.GetCodeVerifier()).Returns("mock_code_verifier");

            httpResponseMock.Content = new StringContent(@"{
                ""access_token"": ""mock_access_token"",
                ""token_type"": ""bearer"",
                ""expires_in"": 3600,
                ""refresh_token"": ""mock_refresh_token"",
                ""scope"": ""scope1 scope2""
            }");

            var oauthHandler = new OAuth2Authenticator(codeVerifierStoreMock.Object, httpClientFactoryMock.Object);
            var appCredentials = new ClientCredentials("mock_client_id", "mock_client_secret");
            string redirectUri = "https://example.com/callback";
            string accessScope = "scope1 scope2";

            var authorizationServerDefinition = new AuthorizationServerDefinitionMock(null, null, null, null, null);

            // Act
            var authUri = oauthHandler.GenerateAuthorizeUri(authorizationServerDefinition, appCredentials, redirectUri, accessScope, "mock_state", null);

            // Assert
            Assert.IsNotNull(authUri);
            Assert.IsTrue(authUri.AbsoluteUri.Contains("response_type=code"));
            Assert.IsTrue(authUri.AbsoluteUri.Contains("client_id=mock_client_id"));
            Assert.IsTrue(authUri.AbsoluteUri.Contains("state=mock_state"));
            Assert.IsTrue(authUri.AbsoluteUri.Contains("scope=scope1%20scope2"));
            Assert.IsTrue(authUri.AbsoluteUri.Contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
        }

        [Test]
        public async Task ProcessUserResponse_ValidResponse_ReturnsAccessToken()
        {
            // Arrange
            var codeVerifierStoreMock = new Mock<ICodeVerifierStore>();
            var httpClientFactoryMock = new Mock<Func<HttpClient>>();
            var httpResponseMock = new HttpResponseMessage(HttpStatusCode.OK);
            var mockHttpHandler = new Mock<HttpMessageHandler>();
            mockHttpHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                               .ReturnsAsync(httpResponseMock);
            var httpClientMock = new HttpClient(mockHttpHandler.Object);

            httpClientFactoryMock.Setup(f => f()).Returns(httpClientMock);

            httpResponseMock.Content = new StringContent(@"{
                ""access_token"": ""mock_access_token"",
                ""token_type"": ""bearer"",
                ""expires_in"": 3600,
                ""refresh_token"": ""mock_refresh_token"",
                ""scope"": ""scope1 scope2""
            }");

            var oauthHandler = new OAuth2Authenticator(codeVerifierStoreMock.Object, httpClientFactoryMock.Object);
            var appCredentials = new ClientCredentials("mock_client_id", "mock_client_secret");
            string redirectUri = "https://example.com/callback";
            var responseUri = new Uri("https://example.com/callback?code=mock_auth_code&state=mock_state");

            // Act
            var result = await oauthHandler.HandleCallback(CreateMockAuthorizationServerDefinition(), appCredentials, responseUri, redirectUri, state => state == "mock_state");

            // Assert
            Assert.IsNotNull(result);
            Assert.IsInstanceOf<AuthorizationSuccessResponse>(result);
            var successResult = (AuthorizationSuccessResponse)result;
            Assert.AreEqual("mock_access_token", successResult.AccessToken);
            Assert.AreEqual("bearer", successResult.TokenType);
            Assert.AreEqual(3600, successResult.ExpiresIn);
            Assert.AreEqual("mock_refresh_token", successResult.RefreshToken);
            Assert.AreEqual("scope1 scope2", successResult.Scope);
        }

        [Test]
        public void GetAuthorizationUri_WithValidParameters_ReturnsAuthorizationUri()
        {
            // Arrange
            var oauthHandler = new OAuth2Authenticator(CreateMockCodeVerifierStore(), () => new HttpClient());
            var appCredentials = new ClientCredentials("client_id", "client_secret");
            var redirectUri = "https://example.com/callback";
            var accessScope = "scope1 scope2";
            var mockAuthorizationServerDefinition = CreateMockAuthorizationServerDefinition();

            // Act
            var result = oauthHandler.GenerateAuthorizeUri(mockAuthorizationServerDefinition, appCredentials, redirectUri, accessScope, "mock_state", null);

            // Assert
            Assert.NotNull(result);
            StringAssert.IsMatch("https:\\/\\/example\\.com\\/authorize\\?client_id=mock_client_id&response_type=code&code_challenge=.*", result.AbsoluteUri);
        }

        [Test]
        public void GetAuthorizationUri_WithCodeVerifierStore_ReturnsAuthorizationUriWithCodeChallenge()
        {
            // Arrange
            var oauthHandler = new OAuth2Authenticator(CreateMockCodeVerifierStore(), () => new HttpClient());
            var appCredentials = new ClientCredentials("client_id", "client_secret");
            var redirectUri = "https://example.com/callback";
            var accessScope = "scope1 scope2";
            var mockAuthorizationServerDefinition = CreateMockAuthorizationServerDefinition();

            // Act
            var result = oauthHandler.GenerateAuthorizeUri(mockAuthorizationServerDefinition, appCredentials, redirectUri, accessScope, "mock_state", null);

            // Assert
            Assert.NotNull(result);
            StringAssert.Contains("code_challenge=", result.AbsoluteUri);
            StringAssert.Contains("code_challenge_method=S256", result.AbsoluteUri);
        }

        [Test]
        public void GetAuthorizationUri_WithNullCodeVerifierStore_DoesNotIncludeCodeChallenge()
        {
            // Arrange
            var oauthHandler = new OAuth2Authenticator(null, () => new HttpClient());
            var appCredentials = new ClientCredentials("client_id", "client_secret");
            var redirectUri = "https://example.com/callback";
            var accessScope = "scope1 scope2";
            var mockAuthorizationServerDefinition = CreateMockAuthorizationServerDefinition();

            // Act
            var result = oauthHandler.GenerateAuthorizeUri(mockAuthorizationServerDefinition, appCredentials, redirectUri, accessScope, "mock_state", null);

            // Assert
            Assert.NotNull(result);
            StringAssert.DoesNotContain("code_challenge=", result.AbsoluteUri);
            StringAssert.DoesNotContain("code_challenge_method=S256", result.AbsoluteUri);
        }

        [Test]
        public void GetAuthorizationUri_NullAuthorizationServerDefinition_ThrowsArgumentNullException()
        {
            // Arrange
            var oauthHandler = new OAuth2Authenticator(CreateMockCodeVerifierStore(), () => new HttpClient());
            var appCredentials = new ClientCredentials("client_id", "client_secret");
            var redirectUri = "https://example.com/callback";
            var accessScope = "scope1 scope2";
            AuthorizationServerDefinitionBase? authorizationServerDefinition = null;

            // Act and Assert
            #pragma warning disable CS8604 // Possible null reference argument.
            Assert.Throws<ArgumentNullException>(() => oauthHandler.GenerateAuthorizeUri(authorizationServerDefinition, appCredentials, redirectUri, accessScope, "mock_state", null));
            #pragma warning restore CS8604 // Possible null reference argument.
        }

        [Test]
        public void GetAuthorizationUri_NullOAuthCredentials_ThrowsArgumentNullException()
        {
            // Arrange
            var oauthHandler = new OAuth2Authenticator(CreateMockCodeVerifierStore(), () => new HttpClient());
            ClientCredentials? appCredentials = null;
            var redirectUri = "https://example.com/callback";
            var accessScope = "scope1 scope2";
            var mockAuthorizationServerDefinition = CreateMockAuthorizationServerDefinition();

            // Act and Assert
            #pragma warning disable CS8604 // Possible null reference argument.
            Assert.Throws<ArgumentNullException>(() => oauthHandler.GenerateAuthorizeUri(mockAuthorizationServerDefinition, appCredentials, redirectUri, accessScope, "mock_state", null));
            #pragma warning restore CS8604 // Possible null reference argument.
        }

        [Test]
        public void GetAuthorizationUri_NullRedirectUri_ReturnsAuthorizationUri()
        {
            // Arrange
            var oauthHandler = new OAuth2Authenticator(CreateMockCodeVerifierStore(), () => new HttpClient());
            var appCredentials = new ClientCredentials("client_id", "client_secret");
            string? redirectUri = null;
            var accessScope = "scope1 scope2";
            var mockAuthorizationServerDefinition = CreateMockAuthorizationServerDefinition();

            // Act and Assert
            #pragma warning disable CS8604 // Possible null reference argument.
            var result = oauthHandler.GenerateAuthorizeUri(mockAuthorizationServerDefinition, appCredentials, redirectUri, accessScope, "mock_state", null);
            #pragma warning restore CS8604 // Possible null reference argument.
            Assert.NotNull(result);
        }

        [Test]
        public void GetAuthorizationUri_NullAccessScope_SetsEmptyScopeInParameters()
        {
            // Arrange
            var oauthHandler = new OAuth2Authenticator(CreateMockCodeVerifierStore(), () => new HttpClient());
            var appCredentials = new ClientCredentials("client_id", "client_secret");
            var redirectUri = "https://example.com/callback";
            string? accessScope = null;
            var mockAuthorizationServerDefinition = CreateMockAuthorizationServerDefinition();

            // Act
            #pragma warning disable CS8604 // Possible null reference argument.
            var result = oauthHandler.GenerateAuthorizeUri(mockAuthorizationServerDefinition, appCredentials, redirectUri, accessScope, "mock_state", null);
            #pragma warning restore CS8604 // Possible null reference argument.

            // Assert
            Assert.NotNull(result);
            Assert.False(result.AbsoluteUri.Contains("scope="));
        }

        [Test]
        public async Task ProcessUserResponse_ValidResponse_ReturnsAuthorizationSuccessResponse()
        {
            // Arrange
            var expectedAccessToken = "mock_access_token";
            var expectedTokenType = "Bearer";
            var expectedExpiresIn = 3600;
            var expectedRefreshToken = "mock_refresh_token";
            var expectedScope = "scope1 scope2";

            var mockAuthorizationServerDefinition = new Mock<AuthorizationServerDefinitionBase>();
            mockAuthorizationServerDefinition.Setup(def => def.GetAccessTokenRequestParameters(It.IsAny<ClientCredentials>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>())).Returns(
                new Dictionary<string, string>
                {
                    { "code", "mock_auth_code" },
                    { "client_id", "mock_client_id" },
                    { "client_secret", "mock_client_secret" },
                    { "grant_type", "authorization_code" }
                }
            );
            mockAuthorizationServerDefinition.Setup(def => def.TokenEndpointUri).Returns("https://example.com/token");
            mockAuthorizationServerDefinition.Setup(def => def.ParseAccessTokenResult(It.IsAny<string>())).Returns(
                new AuthorizationSuccessResponse(
                    new Dictionary<string, object?>
                    {
                        { "access_token", expectedAccessToken },
                        { "token_type", expectedTokenType },
                        { "expires_in", expectedExpiresIn },
                        { "refresh_token", expectedRefreshToken },
                        { "scope", expectedScope }
                    },
                    expectedAccessToken,
                    expectedTokenType,
                    expectedExpiresIn,
                    expectedRefreshToken,
                    expectedScope,
                    DateTime.UtcNow
                )
            );

            var mockHttpResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(@"{ ""access_token"": ""mock_access_token"", ""token_type"": ""Bearer"", ""expires_in"": 3600, ""refresh_token"": ""mock_refresh_token"", ""scope"": ""scope1 scope2"" }")
            };
            var httpClientFactoryMock = new Mock<Func<HttpClient>>();
            //var httpResponseMock = new HttpResponseMessage(HttpStatusCode.OK);
            var mockHttpHandler = new Mock<HttpMessageHandler>();
            mockHttpHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                               .ReturnsAsync(mockHttpResponse);
            var httpClientMock = new HttpClient(mockHttpHandler.Object);


            httpClientFactoryMock.Setup(f => f()).Returns(httpClientMock);

            var oauthHandler = new OAuth2Authenticator(CreateMockCodeVerifierStore(), httpClientFactoryMock.Object);
            var appCredentials = new ClientCredentials("mock_client_id", "mock_client_secret");
            var responseUri = new Uri("https://example.com/callback?code=mock_auth_code&state=mock_state");
            var redirectUri = "https://example.com/callback";

            // Act
            var result = await oauthHandler.HandleCallback(mockAuthorizationServerDefinition.Object, appCredentials, responseUri, redirectUri, state => state == "mock_state");

            // Assert
            Assert.NotNull(result);
            Assert.IsInstanceOf<AuthorizationSuccessResponse>(result);
            var successResult = (AuthorizationSuccessResponse)result;
            Assert.AreEqual(expectedAccessToken, successResult.AccessToken);
            Assert.AreEqual(expectedTokenType, successResult.TokenType);
            Assert.AreEqual(expectedExpiresIn, successResult.ExpiresIn);
            Assert.AreEqual(expectedRefreshToken, successResult.RefreshToken);
            Assert.AreEqual(expectedScope, successResult.Scope);
        }

        [Test]
        public async Task ProcessUserResponse_ErrorResponse_ReturnsAuthorizationErrorResponse()
        {
            // Arrange
            var expectedError = "invalid_request";
            var expectedErrorDescription = "The request is missing a required parameter";
            var expectedErrorUri = "https://example.com/error";

            var mockAuthorizationServerDefinition = new Mock<AuthorizationServerDefinitionBase>();
            mockAuthorizationServerDefinition.Setup(def => def.ParseAccessTokenResult(It.IsAny<string>())).Returns(
                new AuthorizationErrorResponse(
                    new Dictionary<string, object>
                    {
                        { "error", expectedError },
                        { "error_description", expectedErrorDescription },
                        { "error_uri", expectedErrorUri }
                    },
                    expectedError,
                    expectedErrorDescription,
                    expectedErrorUri
                )
            );

            var mockHttpResponse = new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent(@"{ ""error"": ""invalid_request"", ""error_description"": ""The request is missing a required parameter"", ""error_uri"": ""https://example.com/error"" }")
            };
            var httpClientFactoryMock = new Mock<Func<HttpClient>>();
            var mockHttpHandler = new Mock<HttpMessageHandler>();
            mockHttpHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                               .ReturnsAsync(mockHttpResponse);
            var httpClientMock = new HttpClient(mockHttpHandler.Object);

            httpClientFactoryMock.Setup(f => f()).Returns(httpClientMock);

            var oauthHandler = new OAuth2Authenticator(CreateMockCodeVerifierStore(), httpClientFactoryMock.Object);
            var appCredentials = new ClientCredentials("mock_client_id", "mock_client_secret");
            var responseUri = new Uri("https://example.com/callback?error=invalid_request&error_description=The+request+is+missing+a+required+parameter&error_uri=https%3A%2F%2Fexample.com%2Ferror&state=mock_state");
            string redirectUri = "https://example.com/callback";

            // Act
            var result = await oauthHandler.HandleCallback(mockAuthorizationServerDefinition.Object, appCredentials, responseUri, redirectUri, state => state == "mock_state");

            // Assert
            Assert.NotNull(result);
            Assert.IsInstanceOf<AuthorizationErrorResponse>(result);
            var errorResult = (AuthorizationErrorResponse)result;
            Assert.AreEqual(expectedError, errorResult.Error);
            Assert.AreEqual(expectedErrorDescription, errorResult.Description);
            Assert.AreEqual(expectedErrorUri, errorResult.Uri);
        }

        [Test]
        public void ProcessUserResponse_InvalidState_ThrowsException()
        {
            // Arrange

            var oauthHandler = new OAuth2Authenticator(CreateMockCodeVerifierStore(), () => new HttpClient());
            var appCredentials = new ClientCredentials("mock_client_id", "mock_client_secret");
            var responseUri = new Uri("https://example.com/callback?code=mock_auth_code&state=invalid_state");
            string redirectUri = "https://example.com/callback";

            // Act and Assert
            Assert.ThrowsAsync<Exception>(async () => await oauthHandler.HandleCallback(CreateMockAuthorizationServerDefinition(), appCredentials, responseUri, redirectUri, state=>state=="mock_state"));
        }

        [Test]
        public async Task FullOAuthFlow_ValidAuthorization_ReturnsAccessToken()
        {
            // Arrange
            var expectedAccessToken = "mock_access_token";
            var expectedTokenType = "Bearer";
            var expectedExpiresIn = 3600;
            var expectedRefreshToken = "mock_refresh_token";
            var expectedScope = "scope1 scope2";

            // Mock AuthorizationServerDefinitionBase
            var mockAuthorizationServerDefinition = new Mock<AuthorizationServerDefinitionBase>();
            mockAuthorizationServerDefinition.Setup(def => def.GetAuthorizationRequestParameters(It.IsAny<ClientCredentials>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<AuthorizationSettings>(), It.IsAny<string?>())).Returns(
                new Dictionary<string, string>
                {
                { "client_id", "mock_client_id" },
                { "response_type", "code" },
                { "state", "mock_state" }, // Assuming state store generates "mock_state" for this test
                { "scope", "scope1 scope2" },
                { "redirect_uri", "https://example.com/callback" }
                }
            );
            mockAuthorizationServerDefinition.Setup(def => def.GetAccessTokenRequestParameters(It.IsAny<ClientCredentials>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>())).Returns(
                new Dictionary<string, string>
                {
                { "code", "mock_auth_code" },
                { "client_id", "mock_client_id" },
                { "client_secret", "mock_client_secret" },
                { "grant_type", "authorization_code" }
                }
            );
            mockAuthorizationServerDefinition.Setup(def => def.AuthorizationEndpointUri).Returns("https://example.com/authorize");
            mockAuthorizationServerDefinition.Setup(def => def.TokenEndpointUri).Returns("https://example.com/token");
            mockAuthorizationServerDefinition.Setup(def => def.ParseAccessTokenResult(It.IsAny<string>())).Returns(
                new AuthorizationSuccessResponse(
                    new Dictionary<string, object?>
                    {
                        { "access_token", expectedAccessToken },
                        { "token_type", expectedTokenType },
                        { "expires_in", expectedExpiresIn },
                        { "refresh_token", expectedRefreshToken },
                        { "scope", expectedScope }
                    },
                    expectedAccessToken,
                    expectedTokenType,
                    expectedExpiresIn,
                    expectedRefreshToken,
                    expectedScope,
                    DateTime.UtcNow
                )
            );

            // Mock IStateStore and ICodeVerifierStore
            var mockCodeVerifierStore = new Mock<ICodeVerifierStore>();
            mockCodeVerifierStore.Setup(store => store.GetCodeVerifier()).Returns("mock_code_verifier");
            var mockHttpResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(@"{ ""access_token"": ""mock_access_token"", ""token_type"": ""Bearer"", ""expires_in"": 3600, ""refresh_token"": ""mock_refresh_token"", ""scope"": ""scope1 scope2"" }")
            };
            var httpClientFactoryMock = new Mock<Func<HttpClient>>();
            var mockHttpHandler = new Mock<HttpMessageHandler>();
            mockHttpHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                               .ReturnsAsync(mockHttpResponse);
            var httpClientMock = new HttpClient(mockHttpHandler.Object);

            httpClientFactoryMock.Setup(f => f()).Returns(httpClientMock);


            var oauthHandler = new OAuth2Authenticator(mockCodeVerifierStore.Object, httpClientFactoryMock.Object);
            var appCredentials = new ClientCredentials("mock_client_id", "mock_client_secret");
            var responseUri = new Uri("https://example.com/callback?code=mock_auth_code&state=mock_state");
            string redirectUri = "https://example.com/callback";

            // Act
            var authUri = oauthHandler.GenerateAuthorizeUri(mockAuthorizationServerDefinition.Object, appCredentials, redirectUri, "scope1 scope2", "mock_state", null);
            var result = await oauthHandler.HandleCallback(mockAuthorizationServerDefinition.Object, appCredentials, responseUri, redirectUri, state => state == "mock_state");

            // Assert
            Assert.NotNull(authUri);
            Assert.True(authUri.AbsoluteUri.Contains("state=mock_state")); // Ensure the state is added to the authorization URI
            Assert.NotNull(result);
            Assert.IsInstanceOf<AuthorizationSuccessResponse>(result);
            var successResult = (AuthorizationSuccessResponse)result;
            Assert.AreEqual(expectedAccessToken, successResult.AccessToken);
            Assert.AreEqual(expectedTokenType, successResult.TokenType);
            Assert.AreEqual(expectedExpiresIn, successResult.ExpiresIn);
            Assert.AreEqual(expectedRefreshToken, successResult.RefreshToken);
            Assert.AreEqual(expectedScope, successResult.Scope);
        }
    }
}