using Newtonsoft.Json;
using System.Security.Claims;

namespace [Application Name].UserAuthentication
{
    public class LocalToken
    {
        [JsonProperty("type")]
        public string type { get; set; } = string.Empty;
        [JsonProperty("value")]
        public string value { get; set; } = string.Empty;
        public static List<Claim> Claims(string JsonLocalTokenList)
        {
            List<Claim> result = new List<Claim>();
            if (!string.IsNullOrEmpty(JsonLocalTokenList))
            {
                List<LocalToken>? claims = JsonConvert.DeserializeObject<List<LocalToken>>(JsonLocalTokenList);
                if (claims != null)
                    foreach (LocalToken claim in claims)
                    {
                        result.Add(new Claim(claim.type, claim.value));
                    }
            }
            return result;
        }
        public static string JsonLocalTokenList(List<LocalToken> claims)
        {
            return JsonConvert.SerializeObject(claims);
        }
    }
}
