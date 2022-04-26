namespace Identity.API.Extensions
{
    public class AppSettings
    {
        public string Secret { get; set; }
        public string TimeToLive { get; set; }
        public string Sender { get; set; }
        public string ValidAt { get; set; }
    }
}
