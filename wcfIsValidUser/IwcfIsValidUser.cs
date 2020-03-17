using System.ServiceModel;
using System.ServiceModel.Web;


namespace wcfIsValidUser
{
    [ServiceContract]
    public interface IwcfIsValidUser
    {
        [WebInvoke(Method = "POST", UriTemplate = "/ValidaLogin", ResponseFormat = WebMessageFormat.Json, BodyStyle = WebMessageBodyStyle.Wrapped)]
        [OperationContract]
        result ValidaLogin(string username, string hpass);

        [WebInvoke(Method = "POST", UriTemplate = "/CambiaPass", ResponseFormat = WebMessageFormat.Json, BodyStyle = WebMessageBodyStyle.Wrapped)]
        [OperationContract]
        result CambiaPass(string conductor, string newpass, string oldpass);
    }
}

