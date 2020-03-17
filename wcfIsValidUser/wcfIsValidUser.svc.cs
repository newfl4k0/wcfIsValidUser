using System.Linq;
using System.ServiceModel.Web;
using Microsoft.AspNet.Identity;
using System.ServiceModel.Activation;
using System;

namespace wcfIsValidUser
{
    [AspNetCompatibilityRequirements(RequirementsMode = AspNetCompatibilityRequirementsMode.Allowed)]
    public class wcfLoginDriver : IwcfIsValidUser
    {

        GoPSEntities Modelo = new GoPSEntities();
        AspNetUsers Usuarios = new AspNetUsers();
        AspNetUsers Usuarioss = new AspNetUsers();
        IPasswordHasher PassHasher = new PasswordHasher();

        [WebInvoke(Method = "POST", UriTemplate = "/ValidaLogin", ResponseFormat = WebMessageFormat.Json, BodyStyle = WebMessageBodyStyle.Wrapped)]
        public result ValidaLogin(string username, string hpass)
        {
            System.String original = null;
            IQueryable<AspNetUsers> user = null;
            PasswordVerificationResult pvr = new PasswordVerificationResult();     
            user = Modelo.AspNetUsers.Where(u => u.UserName == username);
            foreach(AspNetUsers u in user)
            { 
                if (!(user.SingleOrDefault().PasswordHash == null ))
                {
                    original = user.SingleOrDefault().PasswordHash;
                }
                pvr = PassHasher.VerifyHashedPassword(original, hpass);
            }            
            if (pvr == PasswordVerificationResult.Failed)
            {
                return new result() { res = false };
            }
            if (pvr == PasswordVerificationResult.Success || pvr == PasswordVerificationResult.SuccessRehashNeeded)
            {
                return new result() { res = true };
            }
            return new result() { res = false };
        }

        [WebInvoke(Method = "POST", UriTemplate = "/CambiaPass", ResponseFormat = WebMessageFormat.Json, BodyStyle = WebMessageBodyStyle.Wrapped)]
        public result CambiaPass(string conductor, string newpass, string oldpass)
        {
            string newhashed = "";
            if (conductor.Length == 0 || newpass.Length == 0 || oldpass.Length == 0)
            {
                return new result() { res = false };
            }
            Usuarios = Modelo.AspNetUsers.Find(conductor);
            if(Usuarios==null)
            {
                return new result() { res = false };
            }
            if(Usuarios.PasswordHash.Length >0)
            {
                IPasswordHasher PassHasher = new PasswordHasher();
                newhashed=PassHasher.HashPassword(newpass);
                AspNetUsers UpdUsuarios = new AspNetUsers();
                PasswordVerificationResult pvr = new PasswordVerificationResult();
                pvr=PassHasher.VerifyHashedPassword(Usuarios.PasswordHash, oldpass);
                if (!(pvr == PasswordVerificationResult.Success))
                {
                    return new result() { res = false };
                }
                int success = 0;
                UpdUsuarios = Usuarios;
                UpdUsuarios.Id = Usuarios.Id;
                UpdUsuarios.Email = Usuarios.Email;
                UpdUsuarios.EmailConfirmed = Usuarios.EmailConfirmed;
                UpdUsuarios.PasswordHash = newhashed;
                UpdUsuarios.SecurityStamp = Usuarios.SecurityStamp;
                UpdUsuarios.PhoneNumber = Usuarios.PhoneNumber;
                UpdUsuarios.PhoneNumberConfirmed = Usuarios.PhoneNumberConfirmed;
                UpdUsuarios.TwoFactorEnabled = Usuarios.TwoFactorEnabled;
                UpdUsuarios.LockoutEndDateUtc = Usuarios.LockoutEndDateUtc;
                UpdUsuarios.LockoutEnabled = Usuarios.LockoutEnabled;
                UpdUsuarios.AccessFailedCount = Usuarios.AccessFailedCount;
                UpdUsuarios.UserName = Usuarios.UserName;
                UpdUsuarios.DateOfBirth = Usuarios.DateOfBirth;
                UpdUsuarios.PicturePath = Usuarios.PicturePath;
                UpdUsuarios.PositionID = Usuarios.PositionID;
                UpdUsuarios.LastLoginDate = Usuarios.LastLoginDate;
                UpdUsuarios.LastLogoutDate = Usuarios.LastLogoutDate;
                UpdUsuarios.IsLoged_in = Usuarios.IsLoged_in;
                UpdUsuarios.Discriminator = Usuarios.Discriminator;
                Modelo.Entry(Usuarios).CurrentValues.SetValues(UpdUsuarios);
                success=Modelo.SaveChanges();
                if(!(success==0))
                {
                    return new result { res = true };
                }
                return new result { res = false };
            }
            return new result { res = false };      
        }     


    }
    public class result
    {
        public bool res { get; set; }
    }
}
