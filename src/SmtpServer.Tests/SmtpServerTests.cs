using MailKit;
using MailKit.Net.Smtp;
using SmtpServer.Authentication;
using SmtpServer.ComponentModel;
using SmtpServer.Mail;
using SmtpServer.Net;
using SmtpServer.Protocol;
using SmtpServer.Storage;
using SmtpServer.Tests.Mocks;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using SmtpResponse = SmtpServer.Protocol.SmtpResponse;

namespace SmtpServer.Tests
{
    public class SmtpServerTests
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public SmtpServerTests()
        {
            MessageStore = new MockMessageStore();
            CancellationTokenSource = new CancellationTokenSource();
        }

        [Fact]
        public void CanReceiveMessage()
        {
            using (CreateServer())
            {
                // act
                MailClient.Send(MailClient.Message(from: "test1@test.com", to: "test2@test.com"));

                // assert
                Assert.Single(MessageStore.Messages);
                Assert.Equal("test1@test.com", MessageStore.Messages[0].Transaction.From.AsAddress());
                Assert.Equal(1, MessageStore.Messages[0].Transaction.To.Count);
                Assert.Equal("test2@test.com", MessageStore.Messages[0].Transaction.To[0].AsAddress());
            }
        }

        [Fact]
        public void CanReceiveMessageUsingStreamingMessageStore()
        {
            var streamingMessageStore = new StreamingMockMessageStore();

            using (CreateServer(services => services.Add(streamingMessageStore)))
            {
                MailClient.Send(MailClient.Message(from: "test1@test.com", to: "test2@test.com", text: "streamed body"));
            }

            Assert.True(streamingMessageStore.StreamingSaveCalled);
            Assert.False(streamingMessageStore.BufferedSaveCalled);
            Assert.Contains("streamed body", streamingMessageStore.Message);
        }

        [Theory]
        [InlineData("Assunto teste acento çãõáéíóú", "utf-8")]
        [InlineData("שלום שלום שלום", "windows-1255")]
        public void CanReceiveUnicodeMimeMessage(string text, string charset)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            using (CreateServer())
            {
                // act
                MailClient.Send(MailClient.Message(subject: text, text: text, charset: charset));

                // assert
                Assert.Single(MessageStore.Messages);
                Assert.Equal(text, MessageStore.Messages[0].MimeMessage.Subject);
                Assert.Equal(text, MessageStore.Messages[0].Text(charset));
            }
        }

        [Fact]
        public void CanAuthenticateUser()
        {
            // arrange
            string user = null;
            string password = null;
            var userAuthenticator = new DelegatingUserAuthenticator((u, p) =>
            {
                user = u;
                password = p;

                return true;
            });

            using (CreateServer(endpoint => endpoint.AllowUnsecureAuthentication(), services => services.Add(userAuthenticator)))
            {
                // act
                MailClient.Send(user: "user", password: "password");

                // assert
                Assert.Single(MessageStore.Messages);
                Assert.Equal("user", user);
                Assert.Equal("password", password);
            }
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("user", "")]
        [InlineData("", "password")]
        public void CanFailAuthenticationEmptyUserOrPassword(string user, string password)
        {
            // arrange
            string actualUser = null;
            string actualPassword = null;
            var userAuthenticator = new DelegatingUserAuthenticator((u, p) =>
            {
                actualUser = u;
                actualPassword = p;

                return false;
            });

            using (CreateServer(endpoint => endpoint.AllowUnsecureAuthentication(), services => services.Add(userAuthenticator)))
            {
                // act and assert
                Assert.Throws<MailKit.Security.AuthenticationException>(() => MailClient.Send(user: user, password: password));

                // assert
                Assert.Empty(MessageStore.Messages);
                Assert.Equal(user, actualUser);
                Assert.Equal(password, actualPassword);
            }
        }

        [Theory]
        [InlineData("AUTH PLAIN not-base64")]
        [InlineData("AUTH LOGIN not-base64")]
        public async Task CanFailInvalidBase64AuthenticationWithoutFaulting(string command)
        {
            var userAuthenticator = new DelegatingUserAuthenticator((user, password) => true);

            using (CreateServer(endpoint => endpoint.AllowUnsecureAuthentication(), services => services.Add(userAuthenticator)))
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var ehloResponse = await rawSmtpClient.SendCommandAsync("EHLO example.com");
                Assert.StartsWith("250-", ehloResponse);

                var response = await rawSmtpClient.SendCommandAsync(command);
                Assert.StartsWith("535 5.7.8 authentication failed", response);

                response = await rawSmtpClient.SendCommandAsync("NOOP");
                Assert.StartsWith("250 2.0.0 Ok", response);
            }
        }

        [Fact]
        public async Task CanFailInvalidBase64AuthenticationContinuationWithoutFaulting()
        {
            var userAuthenticator = new DelegatingUserAuthenticator((user, password) => true);

            using (CreateServer(endpoint => endpoint.AllowUnsecureAuthentication(), services => services.Add(userAuthenticator)))
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var ehloResponse = await rawSmtpClient.SendCommandAsync("EHLO example.com");
                Assert.StartsWith("250-", ehloResponse);

                var response = await rawSmtpClient.SendCommandAsync("AUTH LOGIN");
                Assert.StartsWith("334 VXNlcm5hbWU6", response);

                response = await rawSmtpClient.SendCommandAsync("not-base64");
                Assert.StartsWith("535 5.7.8 authentication failed", response);

                response = await rawSmtpClient.SendCommandAsync("NOOP");
                Assert.StartsWith("250 2.0.0 Ok", response);
            }
        }

        [Fact]
        public async Task CanReturnStableEhloResponse()
        {
            using (CreateServer())
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("EHLO example.com");

                Assert.Equal(
                   "250-localhost Hello example.com, haven't we met before?\r\n" +
                   "250-PIPELINING\r\n" +
                   "250-8BITMIME\r\n" +
                   "250-SMTPUTF8\r\n" +
                   "250-DSN\r\n" +
                   "250 CHUNKING\r\n",
                   response);
            }
        }

        [Fact]
        public void CanReceiveBccInMessageTransaction()
        {
            using (CreateServer())
            {
                // act
                MailClient.Send(MailClient.Message(from: "test1@test.com", to: "test2@test.com", cc: "test3@test.com", bcc: "test4@test.com"));

                // assert
                Assert.Single(MessageStore.Messages);
                Assert.Equal("test1@test.com", MessageStore.Messages[0].Transaction.From.AsAddress());
                Assert.Equal(3, MessageStore.Messages[0].Transaction.To.Count);
                Assert.Equal("test2@test.com", MessageStore.Messages[0].Transaction.To[0].AsAddress());
                Assert.Equal("test3@test.com", MessageStore.Messages[0].Transaction.To[1].AsAddress());
                Assert.Equal("test4@test.com", MessageStore.Messages[0].Transaction.To[2].AsAddress());
            }
        }

        [Fact]
        public async Task CanReturnHelpResponse()
        {
            using (CreateServer())
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("HELP");

                Assert.StartsWith("214 2.0.0 Commands:", response);
                Assert.Contains("HELP", response);
                Assert.Contains("VRFY", response);
                Assert.Contains("EXPN", response);
            }
        }

        [Fact]
        public async Task VrfyAndExpnDoNotEnumerateByDefault()
        {
            using (CreateServer())
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("VRFY user@example.com");
                Assert.Equal("252 2.5.2 cannot VRFY user, but will accept message and attempt delivery\r\n", response);

                response = await rawSmtpClient.SendCommandAsync("EXPN staff");
                Assert.Equal("252 2.5.2 cannot EXPN mailing list\r\n", response);

                response = await rawSmtpClient.SendCommandAsync("NOOP");
                Assert.StartsWith("250 2.0.0 Ok", response);
            }
        }

        [Fact]
        public async Task CanUseCustomSmtpCommandPolicy()
        {
            var policy = new TestSmtpCommandPolicy();

            using (CreateServer(services => services.Add(policy)))
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("HELP VRFY");
                Assert.Equal("214 2.0.0 Custom help for VRFY\r\n", response);

                response = await rawSmtpClient.SendCommandAsync("VRFY user@example.com");
                Assert.Equal("250 2.0.0 user@example.com\r\n", response);

                response = await rawSmtpClient.SendCommandAsync("EXPN staff");
                Assert.Equal("250 2.0.0 member@example.com\r\n", response);
            }
        }

        [Fact]
        public async Task CanReceiveMessageUsingBdatLast()
        {
            using (CreateServer())
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("EHLO example.com");
                Assert.Contains("CHUNKING", response);

                response = await rawSmtpClient.SendCommandAsync("MAIL FROM:<sender@example.com>");
                Assert.StartsWith("250 2.0.0 Ok", response);

                response = await rawSmtpClient.SendCommandAsync("RCPT TO:<recipient@example.com>");
                Assert.StartsWith("250 2.0.0 Ok", response);

                const string message = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: BDAT\r\n\r\nchunked body\r\n";
                response = await rawSmtpClient.SendBdatAsync($"BDAT {message.Length} LAST", message);
                Assert.StartsWith("250 2.0.0 Ok", response);
            }

            var stored = Assert.Single(MessageStore.Messages);
            Assert.Equal("chunked body", stored.Text());
        }

        [Fact]
        public async Task CanReceiveMessageUsingMultipleBdatChunks()
        {
            using (CreateServer())
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("EHLO example.com");
                Assert.Contains("CHUNKING", response);

                response = await rawSmtpClient.SendCommandAsync("MAIL FROM:<sender@example.com>");
                Assert.StartsWith("250 2.0.0 Ok", response);

                response = await rawSmtpClient.SendCommandAsync("RCPT TO:<recipient@example.com>");
                Assert.StartsWith("250 2.0.0 Ok", response);

                const string part1 = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: BDAT\r\n\r\n";
                const string part2 = "chunked body\r\n";

                response = await rawSmtpClient.SendBdatAsync($"BDAT {part1.Length}", part1);
                Assert.StartsWith("250 2.0.0 Ok", response);
                Assert.Empty(MessageStore.Messages);

                response = await rawSmtpClient.SendBdatAsync($"BDAT {part2.Length} LAST", part2);
                Assert.StartsWith("250 2.0.0 Ok", response);
            }

            var stored = Assert.Single(MessageStore.Messages);
            Assert.Equal("chunked body", stored.Text());
        }

        [Fact]
        public async Task BufferedBdatPassesBoundedSequenceToMessageStore()
        {
            var messageStore = new BufferedSequenceInspectingMessageStore();

            using (CreateServer(services => services.Add(messageStore)))
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("EHLO example.com");
                Assert.Contains("CHUNKING", response);

                response = await rawSmtpClient.SendCommandAsync("MAIL FROM:<sender@example.com>");
                Assert.StartsWith("250 2.0.0 Ok", response);

                response = await rawSmtpClient.SendCommandAsync("RCPT TO:<recipient@example.com>");
                Assert.StartsWith("250 2.0.0 Ok", response);

                var part1 = Encoding.UTF8.GetBytes("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: BDAT\r\n\r\n");
                var part2 = Encoding.UTF8.GetBytes("bounded buffered body with unicode þæö\r\n");

                response = await rawSmtpClient.SendBdatAsync($"BDAT {part1.Length}", part1);
                Assert.StartsWith("250 2.0.0 Ok", response);

                response = await rawSmtpClient.SendBdatAsync($"BDAT {part2.Length} LAST", part2);
                Assert.StartsWith("250 2.0.0 Ok", response);

                var expected = part1.Concat(part2).ToArray();

                Assert.True(messageStore.SaveCalled);
                Assert.Equal(expected.Length, messageStore.BufferLength);
                Assert.Equal(expected.Length, messageStore.FirstSegmentLength);
                Assert.Equal(expected, messageStore.Message);
            }
        }

        [Fact]
        public async Task CanReceiveMessageUsingStreamingBdatChunks()
        {
            var streamingMessageStore = new StreamingMockMessageStore();

            using (CreateServer(services => services.Add(streamingMessageStore)))
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("EHLO example.com");
                Assert.Contains("CHUNKING", response);

                response = await rawSmtpClient.SendCommandAsync("MAIL FROM:<sender@example.com>");
                Assert.StartsWith("250 2.0.0 Ok", response);

                response = await rawSmtpClient.SendCommandAsync("RCPT TO:<recipient@example.com>");
                Assert.StartsWith("250 2.0.0 Ok", response);

                const string part1 = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: BDAT\r\n\r\n";
                const string part2 = "streamed body\r\n";

                response = await rawSmtpClient.SendBdatAsync($"BDAT {part1.Length}", part1);
                Assert.StartsWith("250 2.0.0 Ok", response);

                response = await rawSmtpClient.SendBdatAsync($"BDAT {part2.Length} LAST", part2);
                Assert.StartsWith("250 2.0.0 Ok", response);
            }

            Assert.True(streamingMessageStore.StreamingSaveCalled);
            Assert.False(streamingMessageStore.BufferedSaveCalled);
            Assert.Contains("streamed body", streamingMessageStore.Message);
        }

        [Fact]
        public async Task BdatHonorsStrictMessageSizeLimit()
        {
            using (CreateServer(c => c.MaxMessageSize(50, MaxMessageSizeHandling.Strict)))
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("EHLO example.com");
                Assert.Contains("CHUNKING", response);

                response = await rawSmtpClient.SendCommandAsync("MAIL FROM:<sender@example.com>");
                Assert.StartsWith("250 2.0.0 Ok", response);

                response = await rawSmtpClient.SendCommandAsync("RCPT TO:<recipient@example.com>");
                Assert.StartsWith("250 2.0.0 Ok", response);

                response = await rawSmtpClient.SendBdatAsync("BDAT 51 LAST", new string('x', 51));
                Assert.Equal("552 5.3.4 message size exceeds fixed maximium message size\r\n", response);
            }

            Assert.Empty(MessageStore.Messages);
        }

        [Fact]
        public async Task CanReceiveDsnEnvelopeParameters()
        {
            IReadOnlyDictionary<string, string> filterParameters = null;
            var mailboxFilter = new ParameterizedMailboxFilter((context, to, from, parameters, cancellationToken) =>
            {
                filterParameters = parameters;
                return Task.FromResult(true);
            });

            using (CreateServer(services => services.Add(mailboxFilter)))
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("EHLO example.com");
                Assert.Contains("DSN", response);

                response = await rawSmtpClient.SendCommandAsync("MAIL FROM:<sender@example.com> RET=FULL ENVID=abc123");
                Assert.StartsWith("250 2.0.0 Ok", response);

                response = await rawSmtpClient.SendCommandAsync("RCPT TO:<recipient@example.com> notify=SUCCESS,FAILURE orcpt=rfc822;original@example.com");
                Assert.StartsWith("250 2.0.0 Ok", response);

                response = await rawSmtpClient.SendCommandAsync("DATA");
                Assert.StartsWith("354", response);

                response = await rawSmtpClient.SendCommandAsync("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: DSN\r\n\r\nbody\r\n.");
                Assert.StartsWith("250 2.0.0 Ok", response);
            }

            Assert.Single(MessageStore.Messages);
            var transaction = MessageStore.Messages[0].Transaction;
            Assert.Equal("FULL", transaction.Parameters["ret"]);
            Assert.Equal("abc123", transaction.Parameters["ENVID"]);

            var recipient = Assert.Single(transaction.GetRecipients());
            Assert.Equal("recipient@example.com", recipient.Address.AsAddress());
            Assert.Equal("SUCCESS,FAILURE", recipient.Parameters["NOTIFY"]);
            Assert.Equal("rfc822;original@example.com", recipient.Parameters["ORCPT"]);

            Assert.NotNull(filterParameters);
            Assert.Equal("SUCCESS,FAILURE", filterParameters["notify"]);
            Assert.Equal("rfc822;original@example.com", filterParameters["orcpt"]);
        }

        [Fact(Skip = "Command timeout wont work properly until https://github.com/dotnet/corefx/issues/15033")]
        public void WillTimeoutWaitingForCommand()
        {
            using (CreateServer(c => c.CommandWaitTimeout(TimeSpan.FromSeconds(1))))
            {
                var client = MailClient.Client();
                client.NoOp();

                for (var i = 0; i < 5; i++)
                {
                    Task.Delay(TimeSpan.FromMilliseconds(250)).Wait();
                    client.NoOp();
                }

                Task.Delay(TimeSpan.FromSeconds(5)).Wait();

                Assert.Throws<IOException>(() => client.NoOp());
            }
        }

        [Fact]
        public void WillTerminateDueToTooMuchData()
        {
            var maxAcceptedMailMessageSize = 50;

            var largeMailContent = string.Concat(Enumerable.Repeat("Too long for 1024 bytes", 1000));
            using var mailMessage = MailClient.Message(from: "test1@test.com", to: "test2@test.com", text: largeMailContent);

            using (CreateServer(c => c.MaxMessageSize(maxAcceptedMailMessageSize, MaxMessageSizeHandling.Strict)))
            {
                Assert.Throws<SmtpCommandException>(() => MailClient.Send(mailMessage));
            }
        }

        [Fact]
        public async Task MaxMessageSizeDoesNotLimitCommandLine()
        {
            using (CreateServer(c => c.MaxMessageSize(10, MaxMessageSizeHandling.Strict)))
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("EHLO command-line.example.com");

                Assert.StartsWith("250-", response);
            }
        }

        [Fact]
        public async Task MaxCommandLineLengthLimitsCommandLine()
        {
            using (CreateServer(c => c.MaxCommandLineLength(10)))
            using (var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025))
            {
                Assert.True(await rawSmtpClient.ConnectAsync());

                var response = await rawSmtpClient.SendCommandAsync("NOOP too-long");

                Assert.StartsWith("501 5.5.2 command line length exceeds maximum command line length", response);
            }
        }

        [Fact]
        public async Task WillSessionTimeoutDuringMailDataTransmission()
        {
            var sessionTimeout = TimeSpan.FromSeconds(5);
            var commandWaitTimeout = TimeSpan.FromSeconds(1);

            using var disposable = CreateServer(
                serverOptions => serverOptions.CommandWaitTimeout(commandWaitTimeout),
                endpointDefinition => endpointDefinition.SessionTimeout(sessionTimeout));

            var stopwatch = new Stopwatch();
            stopwatch.Start();

            using var rawSmtpClient = new RawSmtpClient("127.0.0.1", 9025);
            await rawSmtpClient.ConnectAsync();

            var response = await rawSmtpClient.SendCommandAsync("helo test");
            if (!response.StartsWith("250"))
            {
                Assert.Fail("helo command not successful");
            }

            response = await rawSmtpClient.SendCommandAsync("mail from:<sender@test.com>");
            if (!response.StartsWith("250"))
            {
                Assert.Fail("mail from command not successful");
            }

            response = await rawSmtpClient.SendCommandAsync("rcpt to:<recipient@test.com>");
            if (!response.StartsWith("250"))
            {
                Assert.Fail("rcpt to command not successful");
            }

            response = await rawSmtpClient.SendCommandAsync("data");
            if (!response.StartsWith("354"))
            {
                Assert.Fail("data command not successful");
            }

            string smtpResponse = null;

            _ = Task.Run (async() =>
            {
                smtpResponse = await rawSmtpClient.WaitForDataAsync();
            });

            var isSessionCancelled = false;

            try
            {
                for (var i = 0; i < 1000; i++)
                {
                    await rawSmtpClient.SendDataAsync("some text part ");
                    await Task.Delay(100);
                }
            }
            catch (IOException)
            {
                isSessionCancelled = true;
                stopwatch.Stop();
            }
            catch (Exception exception)
            {
                Assert.Fail($"Wrong exception type {exception.GetType()}");
            }

            Assert.True(isSessionCancelled, "Smtp session is not cancelled");
            Assert.Equal("554 5.0.0\r\n221 2.0.0 The session has be cancelled.\r\n", smtpResponse);

            Assert.True(stopwatch.Elapsed > sessionTimeout, "SessionTimeout not reached");
        }

        [Fact]
        public void CanReturnSmtpResponseException_DoesNotQuit()
        {
            // arrange
            var mailboxFilter = new DelegatingMailboxFilter(@from =>
            {
                throw new SmtpResponseException(SmtpResponse.AuthenticationRequired);

#pragma warning disable 162
                return true;
#pragma warning restore 162
            });

            using (CreateServer(services => services.Add(mailboxFilter)))
            {
                using var client = MailClient.Client();

                Assert.Throws<ServiceNotAuthenticatedException>(() => client.Send(MailClient.Message()));

                client.NoOp();
            }
        }

        [Fact]
        public void CanReturnSmtpResponseException_SessionWillQuit()
        {
            // arrange
            var mailboxFilter = new DelegatingMailboxFilter(@from => throw new SmtpResponseException(SmtpResponse.AuthenticationRequired, true));

            using (CreateServer(services => services.Add(mailboxFilter)))
            {
                using var client = MailClient.Client();

                Assert.Throws<ServiceNotAuthenticatedException>(() => client.Send(MailClient.Message()));

                // no longer connected to this is invalid
                Assert.ThrowsAny<Exception>(() => client.NoOp());
            }
        }

        [Fact]
        public void CanForceUserAuthentication_DoesNotThrowIfLoginIsSent()
        {
            var userAuthenticator = new DelegatingUserAuthenticator((user, password) => true);

            using (CreateServer(endpoint => endpoint.AllowUnsecureAuthentication().AuthenticationRequired(), services => services.Add(userAuthenticator)))
            {
                MailClient.Send(user: "user", password: "password");
            }
        }

        [Fact]
        public void CanForceUserAuthentication_ThrowsIfLoginIsNotSent()
        {
            var userAuthenticator = new DelegatingUserAuthenticator((user, password) => true);

            using (CreateServer(endpoint => endpoint.AllowUnsecureAuthentication().AuthenticationRequired(), services => services.Add(userAuthenticator)))
            {
                Assert.Throws<ServiceNotAuthenticatedException>(() => MailClient.Send());
            }
        }

        [Fact]
        public void DoesNotSecureTheSessionWhenCertificateIsEmpty()
        {
            using (var disposable = CreateServer())
            {
                ISessionContext sessionContext = null;
                var sessionCreatedHandler = new EventHandler<SessionEventArgs>(
                    delegate (object sender, SessionEventArgs args)
                    {
                        sessionContext = args.Context;
                    });

                disposable.Server.SessionCreated += sessionCreatedHandler;

                MailClient.Send();

                disposable.Server.SessionCreated -= sessionCreatedHandler;

                Assert.False(sessionContext.Pipe.IsSecure);
            }

            ServicePointManager.ServerCertificateValidationCallback = null;
        }

        [Fact]
        public void SecuresTheSessionWhenCertificateIsSupplied()
        {
            using var disposable = CreateServer(options => options.Certificate(CreateCertificate()));

            var isSecure = false;
            var sessionCreatedHandler = new EventHandler<SessionEventArgs>(
                delegate (object sender, SessionEventArgs args)
                {
                    args.Context.CommandExecuted += (_, commandArgs) =>
                    {
                        isSecure = commandArgs.Context.Pipe.IsSecure;
                    };
                });

            disposable.Server.SessionCreated += sessionCreatedHandler;

            MailClient.Send();

            disposable.Server.SessionCreated -= sessionCreatedHandler;

            Assert.True(isSecure);
        }

        [Fact]
        public void SecuresTheSessionByDefault()
        {
            using var disposable = CreateServer(endpoint => endpoint.IsSecure(true).Certificate(CreateCertificate()));

            var isSecure = false;
            var sessionCreatedHandler = new EventHandler<SessionEventArgs>(
                delegate (object sender, SessionEventArgs args)
                {
                    args.Context.CommandExecuted += (_, commandArgs) =>
                    {
                        isSecure = commandArgs.Context.Pipe.IsSecure;
                    };
                });

            disposable.Server.SessionCreated += sessionCreatedHandler;

            MailClient.NoOp(MailKit.Security.SecureSocketOptions.SslOnConnect);

            disposable.Server.SessionCreated -= sessionCreatedHandler;

            Assert.True(isSecure);
        }

        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        [Fact]
        public async Task SessionTimeoutIsExceeded_DelayedAuthenticate()
        {
            var sessionTimeout = TimeSpan.FromSeconds(3);
            var server = "localhost";
            var port = 9025;

            using var disposable = CreateServer(endpoint => endpoint
                .SessionTimeout(sessionTimeout)
                .IsSecure(true)
                .Certificate(CreateCertificate())
            );

            using var tcpClient = new TcpClient(server, port);
            using var sslStream = new SslStream(tcpClient.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

            await Task.Delay(sessionTimeout.Add(TimeSpan.FromSeconds(1)));

            var exception = await Assert.ThrowsAsync<IOException>(async () =>
            {
                await sslStream.AuthenticateAsClientAsync(server);
            });
        }

        [Fact]
        public async Task SessionTimeoutIsExceeded_NoCommands()
        {
            var sessionTimeout = TimeSpan.FromSeconds(3);
            var server = "localhost";
            var port = 9025;

            using var disposable = CreateServer(endpoint => endpoint
                                        .SessionTimeout(sessionTimeout)
                                        .IsSecure(true)
                                        .Certificate(CreateCertificate())
                                   );

            var stopwatch = new Stopwatch();
            stopwatch.Start();

            using var tcpClient = new TcpClient(server, port);
            using var sslStream = new SslStream(tcpClient.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

            await sslStream.AuthenticateAsClientAsync(server);

            if (sslStream.IsAuthenticated)
            {
                var buffer = new byte[1024];

                var welcomeByteCount = await sslStream.ReadAsync(buffer, 0, buffer.Length);

                var emptyResponseCount = await sslStream.ReadAsync(buffer, 0, buffer.Length);

                await Task.Delay(100); //Add a tolerance
                stopwatch.Stop();

                Assert.True(emptyResponseCount == 0, "Some data received");
                Assert.True(stopwatch.Elapsed > sessionTimeout, $"SessionTimout not elapsed {stopwatch.Elapsed}");
            }
            else
            {
                Assert.Fail("Smtp Session is not authenticated");
            }
        }

        [Fact]
        public void ServerCanBeSecuredAndAuthenticated()
        {
            var userAuthenticator = new DelegatingUserAuthenticator((user, password) => true);

            using var disposable = CreateServer(
                endpoint => endpoint.AllowUnsecureAuthentication(true).Certificate(CreateCertificate()).SupportedSslProtocols(SslProtocols.Tls12),
                services => services.Add(userAuthenticator));

            var isSecure = false;
            ISessionContext sessionContext = null;
            var sessionCreatedHandler = new EventHandler<SessionEventArgs>(
                delegate (object sender, SessionEventArgs args)
                {
                    sessionContext = args.Context;
                    sessionContext.CommandExecuted += (_, commandArgs) =>
                    {
                        isSecure = commandArgs.Context.Pipe.IsSecure;
                    };
                });

            disposable.Server.SessionCreated += sessionCreatedHandler;

            MailClient.Send(user: "user", password: "password");

            disposable.Server.SessionCreated -= sessionCreatedHandler;

            Assert.True(isSecure);
            Assert.True(sessionContext.Authentication.IsAuthenticated);
        }

        [Fact]
        public void EndpointListenerWillRaiseEndPointEvents()
        {
            var endpointListenerFactory = new EndpointListenerFactory();

            var started = false;
            var stopped = false;

            endpointListenerFactory.EndpointStarted += (sender, e) => { started = true; };
            endpointListenerFactory.EndpointStopped += (sender, e) => { stopped = true; };

            using (CreateServer(services => services.Add(endpointListenerFactory)))
            {
                MailClient.Send();
            }

            Assert.True(started);
            Assert.True(stopped);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        public void CanNotConfigureInvalidNetworkBufferSize(int value)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new SmtpServerOptionsBuilder().NetworkBufferSize(value));
        }

        public static X509Certificate2 CreateSelfSignedCertificate(string subjectName)
        {
            var validityPeriodInYears = 1;

            using RSA rsa = RSA.Create(2048);  // 2048-Bit Key

            var certificateRequest = new CertificateRequest(
                $"CN={subjectName}",  // Common Name (CN)
                rsa,
                HashAlgorithmName.SHA256,  // Hash-Algorithmus
                RSASignaturePadding.Pkcs1  // Padding Schema
            );

            certificateRequest.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false)
            );

            certificateRequest.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true)
            );

            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddYears(validityPeriodInYears);

            X509Certificate2 certificate = certificateRequest.CreateSelfSigned(notBefore, notAfter);

            return new X509Certificate2(certificate.Export(X509ContentType.Pfx));
        }

        public static X509Certificate2 CreateCertificate()
        {
            return CreateSelfSignedCertificate("localhost");
        }

        /// <summary>
        /// Create a running instance of a server.
        /// </summary>
        /// <returns>A disposable instance which will close and release the server instance.</returns>
        SmtpServerDisposable CreateServer()
        {
            return CreateServer(_ => { }, _ => { }, _ => { });
        }

        /// <summary>
        /// Create a running instance of a server.
        /// </summary>
        /// <param name="serverConfiguration">The configuration to apply to run the server.</param>
        /// <returns>A disposable instance which will close and release the server instance.</returns>
        SmtpServerDisposable CreateServer(Action<SmtpServerOptionsBuilder> serverConfiguration)
        {
            return CreateServer(serverConfiguration, endpointConfiguration => { }, services => { });
        }

        /// <summary>
        /// Create a running instance of a server.
        /// </summary>
        /// <param name="endpointConfiguration">The configuration to apply to run the server.</param>
        /// <returns>A disposable instance which will close and release the server instance.</returns>
        SmtpServerDisposable CreateServer(Action<EndpointDefinitionBuilder> endpointConfiguration)
        {
            return CreateServer(server => { }, endpointConfiguration, services => { });
        }

        /// <summary>
        /// Create a running instance of a server.
        /// </summary>
        /// <param name="serverConfiguration">The configuration to apply to run the server.</param>
        /// <param name="endpointConfiguration">The configuration to apply to the endpoint.</param>
        /// <returns>A disposable instance which will close and release the server instance.</returns>
        SmtpServerDisposable CreateServer(Action<SmtpServerOptionsBuilder> serverConfiguration, Action<EndpointDefinitionBuilder> endpointConfiguration)
        {
            return CreateServer(serverConfiguration, endpointConfiguration, services => { });
        }

        /// <summary>
        /// Create a running instance of a server.
        /// </summary>
        /// <param name="endpointConfiguration">The configuration to apply to the endpoint.</param>
        /// <param name="serviceConfiguration">The configuration to apply to the services.</param>
        /// <returns>A disposable instance which will close and release the server instance.</returns>
        SmtpServerDisposable CreateServer(Action<EndpointDefinitionBuilder> endpointConfiguration, Action<ServiceProvider> serviceConfiguration)
        {
            return CreateServer(server => { }, endpointConfiguration, serviceConfiguration);
        }

        /// <summary>
        /// Create a running instance of a server.
        /// </summary>
        /// <param name="serviceConfiguration">The configuration to apply to the services.</param>
        /// <returns>A disposable instance which will close and release the server instance.</returns>
        SmtpServerDisposable CreateServer(Action<ServiceProvider> serviceConfiguration)
        {
            return CreateServer(server => { }, endpoint => { }, serviceConfiguration);
        }

        /// <summary>
        /// Create a running instance of a server.
        /// </summary>
        /// <param name="serverConfiguration">The configuration to apply to run the server.</param>
        /// <param name="endpointConfiguration">The configuration to apply to the endpoint.</param>
        /// <param name="serviceConfiguration">The configuration to apply to the services.</param>
        /// <returns>A disposable instance which will close and release the server instance.</returns>
        SmtpServerDisposable CreateServer(
            Action<SmtpServerOptionsBuilder> serverConfiguration,
            Action<EndpointDefinitionBuilder> endpointConfiguration,
            Action<ServiceProvider> serviceConfiguration)
        {
            var options = new SmtpServerOptionsBuilder()
                .ServerName("localhost")
                .Endpoint(
                    endpointBuilder =>
                    {
                        endpointBuilder.Port(9025);
                        endpointConfiguration(endpointBuilder);
                    });

            serverConfiguration(options);

            var serviceProvider = new ServiceProvider();
            serviceProvider.Add(MessageStore);
            serviceConfiguration?.Invoke(serviceProvider);

            var server = new SmtpServer(options.Build(), serviceProvider);
            var smtpServerTask = server.StartAsync(CancellationTokenSource.Token);

            return new SmtpServerDisposable(server, () =>
            {
                CancellationTokenSource.Cancel();

                try
                {
                    smtpServerTask.Wait();
                }
                catch (AggregateException e)
                {
                    e.Handle(exception => exception is OperationCanceledException);
                }
            });
        }

        /// <summary>
        /// The message store that is being used to store the messages by default.
        /// </summary>
        public MockMessageStore MessageStore { get; }

        /// <summary>
        /// The cancellation token source for the test.
        /// </summary>
        public CancellationTokenSource CancellationTokenSource { get; }

        sealed class StreamingMockMessageStore : MessageStore, IStreamingMessageStore
        {
            public override Task<SmtpResponse> SaveAsync(ISessionContext context, IMessageTransaction transaction, ReadOnlySequence<byte> buffer, CancellationToken cancellationToken)
            {
                BufferedSaveCalled = true;

                return Task.FromResult(SmtpResponse.Ok);
            }

            public async Task<SmtpResponse> SaveAsync(ISessionContext context, IMessageTransaction transaction, PipeReader reader, CancellationToken cancellationToken)
            {
                StreamingSaveCalled = true;

                using var stream = new MemoryStream();

                while (true)
                {
                    var result = await reader.ReadAsync(cancellationToken);
                    var buffer = result.Buffer;

                    foreach (var segment in buffer)
                    {
                        stream.Write(segment.Span);
                    }

                    reader.AdvanceTo(buffer.End);

                    if (result.IsCompleted)
                    {
                        break;
                    }
                }

                Message = Encoding.UTF8.GetString(stream.ToArray());

                return SmtpResponse.Ok;
            }

            public bool BufferedSaveCalled { get; private set; }

            public bool StreamingSaveCalled { get; private set; }

            public string Message { get; private set; }
        }

        sealed class BufferedSequenceInspectingMessageStore : MessageStore
        {
            public override Task<SmtpResponse> SaveAsync(ISessionContext context, IMessageTransaction transaction, ReadOnlySequence<byte> buffer, CancellationToken cancellationToken)
            {
                SaveCalled = true;
                BufferLength = buffer.Length;
                FirstSegmentLength = buffer.First.Length;
                Message = buffer.ToArray();

                return Task.FromResult(SmtpResponse.Ok);
            }

            public bool SaveCalled { get; private set; }

            public long BufferLength { get; private set; }

            public int FirstSegmentLength { get; private set; }

            public byte[] Message { get; private set; }
        }

        sealed class ParameterizedMailboxFilter : MailboxFilter
        {
            readonly Func<ISessionContext, IMailbox, IMailbox, IReadOnlyDictionary<string, string>, CancellationToken, Task<bool>> _canDeliverDelegate;

            public ParameterizedMailboxFilter(
                Func<ISessionContext, IMailbox, IMailbox, IReadOnlyDictionary<string, string>, CancellationToken, Task<bool>> canDeliverDelegate)
            {
                _canDeliverDelegate = canDeliverDelegate;
            }

            public override Task<bool> CanDeliverToAsync(
                ISessionContext context,
                IMailbox to,
                IMailbox @from,
                IReadOnlyDictionary<string, string> parameters,
                CancellationToken cancellationToken)
            {
                return _canDeliverDelegate(context, to, @from, parameters, cancellationToken);
            }
        }

        sealed class TestSmtpCommandPolicy : SmtpCommandPolicy
        {
            public override Task<SmtpResponse> GetHelpAsync(ISessionContext context, string argument, CancellationToken cancellationToken)
            {
                return Task.FromResult(new SmtpResponse(SmtpReplyCode.HelpResponse, $"Custom help for {argument}"));
            }

            public override Task<SmtpResponse> VerifyAsync(ISessionContext context, string argument, CancellationToken cancellationToken)
            {
                return Task.FromResult(new SmtpResponse(SmtpReplyCode.Ok, argument));
            }

            public override Task<SmtpResponse> ExpandAsync(ISessionContext context, string argument, CancellationToken cancellationToken)
            {
                return Task.FromResult(new SmtpResponse(SmtpReplyCode.Ok, "member@example.com"));
            }
        }
    }
}
