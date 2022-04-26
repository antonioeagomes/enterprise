using Microsoft.AspNetCore.Identity;

namespace Identity.API.Extensions
{
    public class IdentityCustomMessages : IdentityErrorDescriber
    {
        public override IdentityError DefaultError()
        {
            return new IdentityError() {  Code = nameof(base.DefaultError), Description = $"Customize an error message"};
        }
    }
}
