namespace Rdpgw.Auth.Database;

public interface IUserDatabase
{
    string GetPassword(string username);
}
