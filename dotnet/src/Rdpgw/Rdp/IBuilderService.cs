namespace Rdpgw.Rdp;

public interface IBuilderService
{
	Task<string> BuildRdpFile(string clientIp, string user, int hostEntryId);
	static abstract byte[] Sign(string rdpContent, string certificatePath, string privateKeyPath);
}