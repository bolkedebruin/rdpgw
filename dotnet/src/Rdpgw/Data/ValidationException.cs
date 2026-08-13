namespace Rdpgw.Data;

public class ValidationException(IEnumerable<string> errors) : Exception(string.Join(Environment.NewLine, errors))
{
	public IEnumerable<string> Errors => errors;
}
