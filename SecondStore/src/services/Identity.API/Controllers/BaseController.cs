using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Identity.API.Controllers
{
    [ApiController]
    public abstract class BaseController : ControllerBase
    {

        protected ICollection<string> Errors = new List<string>();

        protected ActionResult CustomResponse(object result = null)
        {
            if (IsValid())
            {
                return Ok(result);
            }

            return BadRequest(new ValidationProblemDetails(new Dictionary<string, string[]>
            {
                { "Messages", Errors.ToArray() }
            }));

        }

        protected ActionResult CustomResponse(ModelStateDictionary modelState)
        {
            var errors = modelState.Values.SelectMany(e => e.Errors);

            foreach (var item in errors)
            {
                AddError(item.ErrorMessage);
            }

            return CustomResponse();

        }

        protected bool IsValid()
        {
            return !Errors.Any();
        }

        protected void AddError(string message)
        {
            Errors.Add(message);
        }

        protected void ClearErrors()
        {
            Errors.Clear();
        }
    }
}
