using System.ComponentModel.DataAnnotations;

namespace Identity.API.Models
{
    public class UserRegisterDTO
    {
        [Required(ErrorMessage = "{0} is mandatory")]
        [EmailAddress(ErrorMessage = "{0} is invalid format")]
        public string Email { get; set; } 
        
        [Required(ErrorMessage ="{0} is mandatory")]
        [StringLength(34, ErrorMessage = "{0} must have between {2} and {1} characters length", MinimumLength = 6)]
        public string Password { get; set; }

        [Required(ErrorMessage = "{0} is mandatory")]
        [Compare(nameof(Password), ErrorMessage = "Confirmation must match.")]
        public string ConfirmPassword { get; set; }
    }

    public class UserLoginDTO
    {
        [Required(ErrorMessage = "{0} is mandatory")]
        [EmailAddress(ErrorMessage = "{0} is invalid format")]
        public string Email { get; set; }

        [Required(ErrorMessage = "{0} is mandatory")]
        public string Password { get; set; }
    }

    public class LoggedUserResponseDTO
    {
        public LoggedUserResponseDTO(string accessToken, double timeToLive, UserTokenDTO userToken)
        {
            AccessToken = accessToken;
            TimeToLive = timeToLive;
            UserToken = userToken;
        }
       public string AccessToken { get; set; }
       public double TimeToLive { get; set; }
       public  UserTokenDTO UserToken { get; set; }
    }

    public class UserTokenDTO
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public IEnumerable<UserClaimDTO> Claims { get; set; }
    }

    public class UserClaimDTO
    {
        public string Value { get; set; }
        public string Type { get; set; }
    }
}
