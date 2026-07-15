using System.Collections.Generic;
using SmtpServer.Mail;

namespace SmtpServer.Protocol
{
    /// <summary>
    /// Optional SMTP command factory interface for commands with ESMTP parameters.
    /// </summary>
    public interface IParameterizedSmtpCommandFactory : ISmtpCommandFactory
    {
        /// <summary>
        /// Create a RCPT command.
        /// </summary>
        /// <param name="address">The address that the mail is to.</param>
        /// <param name="parameters">The optional recipient parameters.</param>
        /// <returns>The RCPT command.</returns>
        SmtpCommand CreateRcpt(IMailbox address, IReadOnlyDictionary<string, string> parameters);
    }
}
