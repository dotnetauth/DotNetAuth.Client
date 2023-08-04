using DotNetAuth.Client;

namespace DotNetAuth.ClientTests.Mocks
{
    class CodeVerifierStoreMock : ICodeVerifierStore
    {
        private string codeVerifier = "mock_code_verifier";

        public void StoreCodeVerifier(string codeVerifier)
        {
            this.codeVerifier = codeVerifier;
        }

        public string GetCodeVerifier()
        {
            return codeVerifier;
        }
    }

}